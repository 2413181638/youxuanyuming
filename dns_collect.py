# -*- coding: utf-8 -*-
"""
IPv4 采集脚本（深挖版：低速稳态 + 多轮采样 + 200+ 公共DNS）
- 域名来源：优先 domains.txt（每行一个），否则用代码内 DOMAINS
- 解析器来源：优先 dns_servers.txt（每行一个IPv4，建议>=200），否则用内置公共DNS
- 策略：
    * 每个域名进行多轮采样（SAMPLES_PER_DOMAIN 轮）；
    * 每轮：系统DNS(可重试) -> 公共DNS池分波并发；命中也继续扫，聚合所有结果；
    * 轮次/波次/单查询之间加入 sleep + 抖动，降低速率，避免限流/丢包；
    * UDP 失败自动回退 TCP；EDNS payload 1232 降低分片；
    * 解析器熔断：同一解析器在本次运行内多次失败则跳过；
- 异常：全部打印到日志，不影响整体执行；
- 写入：所有域名与轮次完成后，合并去重排序，一次性覆盖写入 ips.txt。
"""

from __future__ import annotations
import sys, os, time, random, ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
from collections import defaultdict

# 依赖：dnspython
try:
    import dns.resolver
    import dns.exception
except ModuleNotFoundError:
    print("缺少 dnspython，请先: pip install dnspython")
    sys.exit(0)  # 不把CI判失败

# =============== 可调参数（为“挖更多”调优过） ===============

# 若不存在 domains.txt，就用这份内置列表
DOMAINS: List[str] = [
    "cloudflare.182682.xyz",
    "bestcf.top",
    "cdn.2020111.xyz",
    "cf.0sm.com",
    "cf.090227.xyz",
    "cf.zhetengsha.eu.org",
    "cfip.1323123.xyz",
    "cnamefuckxxs.yuchen.icu",
    "cloudflare-ip.mofashi.ltd",
    "freeyx.cloudflare88.eu.org",
]

# 若不存在 dns_servers.txt，则用兜底池（建议提供文件扩充到 200+）
BUILTIN_RESOLVERS = [
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    # Google
    "8.8.8.8", "8.8.4.4",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
    # Verisign
    "64.6.64.6", "64.6.65.6",
    # Comodo
    "8.26.56.26", "8.20.247.20",
    # AdGuard
    "94.140.14.14", "94.140.15.15",
    # CleanBrowsing
    "185.228.168.9", "185.228.169.9",
    # Yandex
    "77.88.8.8", "77.88.8.1",
    # Level3(历史)
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # 国内常见（runner 可达性不稳定）
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29",
    "180.76.76.76",
    "1.2.4.8", "210.2.4.8",
]

# 多轮采样（轮次越多越全，但更久）
SAMPLES_PER_DOMAIN = 5          # 每域名轮次 ↑
WAVES_PER_ROUND = 8             # 每轮波次 ↑（每轮扫更多解析器）
RESOLVERS_PER_WAVE = 12         # 每波解析器 ↓（降低瞬时并发）
MAX_WAVES_PER_DOMAIN = 1000     # 总波数上限（安全阈）

# 速率控制（更稳）
SLEEP_BETWEEN_WAVES = 0.8       # 波次间 sleep（秒）
SLEEP_BETWEEN_ROUNDS = 2.0      # 轮次间 sleep（秒）
JITTER_PER_QUERY = (0.05, 0.15) # 单查询前抖动(秒)区间，降低瞬时突刺

# 查询与超时（略放宽）
PER_QUERY_TIMEOUT = 3.5         # 单次查询超时
PER_QUERY_LIFETIME = 4.5        # 单次查询生命周期
RETRIES_PER_RESOLVER = 2        # 每解析器重试
SYSTEM_TRIES = 2                 # 系统DNS尝试次数

# 并发（整体下降）
MAX_WORKERS = min(16, (os.cpu_count() or 2) * 2)

# 解析器熔断/TCP回退/EDNS
RESOLVER_FAIL_THRESHOLD = 3     # 同一解析器连续失败阈值（本次运行内）
ENABLE_TCP_FALLBACK = True
EDNS_PAYLOAD = 1232             # 降低UDP分片

# 文件
DOMAINS_FILE = Path("domains.txt")
RESOLVERS_FILE = Path("dns_servers.txt")
IPS_FILE = Path("ips.txt")

# 日志
PRINT_VERBOSE_ERRORS = True

# 解析器失败计数（本次运行）
RESOLVER_FAIL_COUNT = defaultdict(int)


# ================= 工具函数 =================

def load_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out

def load_domains() -> List[str]:
    domains = load_lines(DOMAINS_FILE) or list(DOMAINS)
    seen, clean = set(), []
    for d in domains:
        d = d.strip().strip(".")
        if d and d not in seen:
            seen.add(d); clean.append(d)
    return clean

def load_resolvers() -> List[str]:
    resolvers = load_lines(RESOLVERS_FILE) or list(BUILTIN_RESOLVERS)
    valid: List[str] = []
    seen: Set[str] = set()
    for ip in resolvers:
        try:
            obj = ipaddress.ip_address(ip)
            if isinstance(obj, ipaddress.IPv4Address) and ip not in seen:
                seen.add(ip); valid.append(ip)
        except ValueError:
            if PRINT_VERBOSE_ERRORS:
                print(f"[WARN] 跳过无效DNS地址: {ip}")
    random.shuffle(valid)  # 打散
    return valid

def is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def make_resolver(use_system: bool, nameserver: str | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=use_system)
    if not use_system and nameserver:
        r.nameservers = [nameserver]
    r.timeout = PER_QUERY_TIMEOUT
    r.lifetime = PER_QUERY_LIFETIME
    try:
        r.use_edns(edns=0, ednsflags=0, payload=EDNS_PAYLOAD)
    except Exception:
        pass
    return r

def query_a_once_with_tcp_fallback(resolver: dns.resolver.Resolver, domain: str, tag: str) -> List[str]:
    """先 UDP，再视情况回退到 TCP。异常打印并返回空列表。"""
    def _do_query(tcp: bool) -> List[str]:
        time.sleep(random.uniform(*JITTER_PER_QUERY))  # 降速抖动
        ips: List[str] = []
        answers = resolver.resolve(domain, "A", raise_on_no_answer=False, tcp=tcp)
        if answers:
            for r in answers:
                ip = getattr(r, "address", "")
                if ip and is_ipv4(ip):
                    ips.append(ip)
        return ips

    try:
        return _do_query(tcp=False)
    except Exception as e1:
        if PRINT_VERBOSE_ERRORS:
            print(f"[ERROR] {domain} via {tag} (UDP) 失败: {type(e1).__name__} - {e1}")
        if ENABLE_TCP_FALLBACK and any(k in type(e1).__name__ for k in ("Timeout", "NoNameservers", "SERVFAIL")):
            try:
                return _do_query(tcp=True)
            except Exception as e2:
                if PRINT_VERBOSE_ERRORS:
                    print(f"[ERROR] {domain} via {tag} (TCP) 失败: {type(e2).__name__} - {e2}")
        return []

def resolve_with_system(domain: str) -> List[str]:
    collected: Set[str] = set()
    sys_resolver = make_resolver(True)
    for i in range(SYSTEM_TRIES):
        ips = query_a_once_with_tcp_fallback(sys_resolver, domain, f"system#{i+1}")
        if ips:
            collected.update(ips)
    return sorted(collected)

def resolve_with_pool_round(domain: str, pool: List[str], start_idx: int) -> List[str]:
    """对公共 DNS 池进行一轮分波并发查询；命中也继续，聚合所有结果。"""
    if not pool:
        return []
    collected: Set[str] = set()

    total = len(pool)
    ordered = pool[start_idx:] + pool[:start_idx]
    max_waves = min(WAVES_PER_ROUND, MAX_WAVES_PER_DOMAIN,
                    (total + RESOLVERS_PER_WAVE - 1) // RESOLVERS_PER_WAVE)

    for wave in range(max_waves):
        start = wave * RESOLVERS_PER_WAVE
        chunk = ordered[start:start + RESOLVERS_PER_WAVE]
        if not chunk:
            break

        with ThreadPoolExecutor(max_workers=min(len(chunk), MAX_WORKERS)) as ex:
            futs = []
            for ns_ip in chunk:
                def attempt(ip=ns_ip):
                    # 熔断：失败太多次直接跳过
                    if RESOLVER_FAIL_COUNT[ip] >= RESOLVER_FAIL_THRESHOLD:
                        if PRINT_VERBOSE_ERRORS:
                            print(f"[SKIP] 解析器 {ip} 已连续失败 {RESOLVER_FAIL_COUNT[ip]} 次，跳过")
                        return []
                    r = make_resolver(False, ip)
                    local: Set[str] = set()
                    for k in range(RETRIES_PER_RESOLVER):
                        ips = query_a_once_with_tcp_fallback(r, domain, f"{ip}#{k+1}")
                        if ips:
                            local.update(ips)
                    if local:
                        RESOLVER_FAIL_COUNT[ip] = 0
                    else:
                        RESOLVER_FAIL_COUNT[ip] += 1
                    return sorted(local)
                futs.append(ex.submit(attempt))

            for fut in as_completed(futs):
                try:
                    ips = fut.result() or []
                except Exception as e:
                    print(f"[FATAL] {domain} 解析器线程异常: {type(e).__name__} - {e}")
                    ips = []
                if ips:
                    collected.update(ips)

        # 波次间降速
        time.sleep(SLEEP_BETWEEN_WAVES)

    return sorted(collected)

def resolve_domain_multi_rounds(domain: str, resolvers: List[str]) -> List[str]:
    """多轮采样：系统DNS + 公共DNS池（每轮旋转起点），累积结果。"""
    collected: Set[str] = set()
    for round_idx in range(SAMPLES_PER_DOMAIN):
        # 系统 DNS
        sys_ips = resolve_with_system(domain)
        if sys_ips:
            collected.update(sys_ips)

        # 公共 DNS 池
        if resolvers:
            start_idx = (round_idx * RESOLVERS_PER_WAVE) % len(resolvers)
            pool_ips = resolve_with_pool_round(domain, resolvers, start_idx=start_idx)
            if pool_ips:
                collected.update(pool_ips)

        # 轮次间降速
        time.sleep(SLEEP_BETWEEN_ROUNDS)

    return sorted(collected)


# ================= 主流程 =================

def main() -> None:
    domains = load_domains()
    resolvers = load_resolvers()

    if not domains:
        print("[INFO] 没有待解析的域名。仍会写入空 ips.txt。")
        IPS_FILE.write_text("", encoding="utf-8")
        return

    print(f"[INFO] 域名数量：{len(domains)}")
    print(f"[INFO] 解析器池：{len(resolvers)} 个（建议 >= 200）")
    print(f"[INFO] 采样轮次：{SAMPLES_PER_DOMAIN}；每轮波次：{WAVES_PER_ROUND}；每波解析器：{RESOLVERS_PER_WAVE}")
    print(f"[INFO] 并发上限：{MAX_WORKERS}；每解析器重试：{RETRIES_PER_RESOLVER}")
    print(f"[INFO] 降速：波次间 {SLEEP_BETWEEN_WAVES}s；轮次间 {SLEEP_BETWEEN_ROUNDS}s；单查询抖动 {JITTER_PER_QUERY[0]}~{JITTER_PER_QUERY[1]}s")

    all_ips: Set[str] = set()

    # 域名级并发（收敛并发，避免总QPS过高）
    with ThreadPoolExecutor(max_workers=min(len(domains), MAX_WORKERS)) as ex:
        future_map = {ex.submit(resolve_domain_multi_rounds, d, resolvers): d for d in domains}
        for fut in as_completed(future_map):
            d = future_map[fut]
            try:
                ips = fut.result()
            except Exception as e:
                print(f"[FATAL] {d} 解析过程中未预期异常: {type(e).__name__} - {e}")
                ips = []
            if ips:
                print(f"[OK] {d:<35} -> {', '.join(ips)}")
                all_ips.update(ips)
            else:
                print(f"[WARN] {d:<35} 未解析到 IPv4")

    # —— 所有域名与轮次完成后，合并去重排序，一次性覆盖写入 —— #
    new_text = "\n".join(sorted(all_ips))
    if new_text:
        new_text += "\n"
    IPS_FILE.write_text(new_text, encoding="utf-8")

    print(f"\n[SAVED] 已写入 {IPS_FILE.resolve()} （{len(all_ips)} 个 IPv4）")
    return


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL-GUARDED] 未预期异常: {type(e).__name__} - {e}")
        try:
            IPS_FILE.write_text("", encoding="utf-8")
        finally:
            sys.exit(0)
