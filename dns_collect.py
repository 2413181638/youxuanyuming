# -*- coding: utf-8 -*-
"""
IPv4 采集脚本（深挖+稳态+预检）
- 多轮采样；系统DNS → 公共DNS池分波并发；命中也继续扫并累计
- 解析器预检（preflight）：先测可达性，超时/失败的DNS本次运行内剔除
- 快速熔断：解析器一旦UDP+TCP均失败，立即隔离（不再使用）
- UDP失败自动回退TCP；EDNS payload 1232 降低UDP分片
- 降速：波次/轮次/单查询抖动，避免被限流
- 所有错误打印，但不阻断流程；所有域名跑完后一次性覆盖写入 ips.txt
"""

from __future__ import annotations
import sys, os, time, random, ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple
from collections import defaultdict

# 依赖
try:
    import dns.resolver
    import dns.exception
except ModuleNotFoundError:
    print("缺少 dnspython，请先: pip install dnspython")
    sys.exit(0)

# ================== 可调参数 ==================

# 域名来源（若有 domains.txt 则优先）
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

# 解析器来源（若有 dns_servers.txt 则优先；建议≥200条且尽量多样化）
BUILTIN_RESOLVERS = [
    "1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112",
    "208.67.222.222","208.67.220.220","64.6.64.6","64.6.65.6","8.26.56.26","8.20.247.20",
    "94.140.14.14","94.140.15.15","185.228.168.9","185.228.169.9","77.88.8.8","77.88.8.1",
    "4.2.2.1","4.2.2.2","4.2.2.3","4.2.2.4","4.2.2.5","4.2.2.6",
    "114.114.114.114","114.114.115.115","223.5.5.5","223.6.6.6","119.29.29.29","180.76.76.76",
    "1.2.4.8","210.2.4.8",
]

# 多轮采样（越大越全，但更久）
SAMPLES_PER_DOMAIN = 5
WAVES_PER_ROUND = 8             # 每轮波次
RESOLVERS_PER_WAVE = 12         # 每波解析器个数（控制并发与QPS）
MAX_WAVES_PER_DOMAIN = 1000

# 降速参数
SLEEP_BETWEEN_WAVES = 0.8       # 波次间sleep
SLEEP_BETWEEN_ROUNDS = 2.0      # 轮次间sleep
JITTER_PER_QUERY = (0.05, 0.15) # 单查询抖动

# 查询/超时
PER_QUERY_TIMEOUT = 3.5
PER_QUERY_LIFETIME = 4.5
RETRIES_PER_RESOLVER = 2
SYSTEM_TRIES = 2

# 并发控制
MAX_WORKERS = min(16, (os.cpu_count() or 2) * 2)

# 解析器预检（preflight）
ENABLE_PREFLIGHT = True
PREFLIGHT_DOMAIN = "one.one.one.one"  # 轻量可缓存域名
PREFLIGHT_TIMEOUT = 1.2               # 预检更短更快
PREFLIGHT_MAX = 600                   # 最多保留多少个健康解析器（防失控）

# 快速熔断/TCP回退/EDNS
RESOLVER_FAIL_THRESHOLD = 1           # 连续失败即隔离（更激进）
ENABLE_TCP_FALLBACK = True
EDNS_PAYLOAD = 1232

# 文件
DOMAINS_FILE = Path("domains.txt")
RESOLVERS_FILE = Path("dns_servers.txt")
IPS_FILE = Path("ips.txt")

# 日志
PRINT_VERBOSE_ERRORS = True

# 运行期状态
RESOLVER_FAIL_COUNT = defaultdict(int)  # 本次运行内的失败次数
QUARANTINED: Set[str] = set()           # 隔离的解析器（不再使用）


# ================== 工具函数 ==================

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
    random.shuffle(valid)
    return valid

def is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def make_resolver(use_system: bool, nameserver: str | None = None,
                  timeout: float | None = None, lifetime: float | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=use_system)
    if not use_system and nameserver:
        r.nameservers = [nameserver]
    r.timeout = timeout if timeout is not None else PER_QUERY_TIMEOUT
    r.lifetime = lifetime if lifetime is not None else PER_QUERY_LIFETIME
    try:
        r.use_edns(edns=0, ednsflags=0, payload=EDNS_PAYLOAD)
    except Exception:
        pass
    return r

def query_a_once_with_tcp_fallback(resolver: dns.resolver.Resolver, domain: str, tag: str) -> List[str]:
    """先UDP→必要时TCP。任何异常都打印并返回空。"""
    def _do_query(tcp: bool) -> List[str]:
        time.sleep(random.uniform(*JITTER_PER_QUERY))
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
        if ENABLE_TCP_FALLBACK and any(k in type(e1).__name__ for k in ("Timeout","NoNameservers","SERVFAIL")):
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

def preflight_filter(pool: List[str]) -> List[str]:
    """解析器预检：对每个候选DNS做一次极轻量查询，Healthy的才保留。"""
    if not ENABLE_PREFLIGHT or not pool:
        return pool
    healthy: List[str] = []
    print(f"[PREFLIGHT] 开始解析器预检，共 {len(pool)} 个候选，超时 {PREFLIGHT_TIMEOUT}s")
    # 用更短的超时以加快预检
    def check(ns_ip: str) -> Tuple[str, bool]:
        if ns_ip in QUARANTINED:
            return ns_ip, False
        r = make_resolver(False, ns_ip, timeout=PREFLIGHT_TIMEOUT, lifetime=PREFLIGHT_TIMEOUT+0.5)
        try:
            _ = r.resolve(PREFLIGHT_DOMAIN, "A", raise_on_no_answer=False, tcp=False)
            return ns_ip, True
        except Exception:
            # UDP失败尝试TCP一次
            try:
                _ = r.resolve(PREFLIGHT_DOMAIN, "A", raise_on_no_answer=False, tcp=True)
                return ns_ip, True
            except Exception:
                return ns_ip, False

    with ThreadPoolExecutor(max_workers=min(32, MAX_WORKERS*2)) as ex:
        futs = {ex.submit(check, ip): ip for ip in pool}
        for fut in as_completed(futs):
            ip, ok = fut.result()
            if ok:
                healthy.append(ip)
    # 随机打散并裁剪到上限，避免极端过大
    random.shuffle(healthy)
    if len(healthy) > PREFLIGHT_MAX:
        healthy = healthy[:PREFLIGHT_MAX]
    print(f"[PREFLIGHT] 通过 {len(healthy)} 个解析器；剔除 {len(pool)-len(healthy)} 个不可达/不稳定")
    return healthy

def resolve_with_pool_round(domain: str, pool: List[str], start_idx: int) -> List[str]:
    """公共DNS池一轮分波并发；命中也继续跑完，聚合所有结果。"""
    if not pool:
        return []
    collected: Set[str] = set()

    total = len(pool)
    ordered = pool[start_idx:] + pool[:start_idx]
    max_waves = min(WAVES_PER_ROUND, MAX_WAVES_PER_DOMAIN,
                    (total + RESOLVERS_PER_WAVE - 1) // RESOLVERS_PER_WAVE)

    for wave in range(max_waves):
        start = wave * RESOLVERS_PER_WAVE
        chunk = [ip for ip in ordered[start:start + RESOLVERS_PER_WAVE] if ip not in QUARANTINED]
        if not chunk:
            time.sleep(SLEEP_BETWEEN_WAVES)
            continue

        with ThreadPoolExecutor(max_workers=min(len(chunk), MAX_WORKERS)) as ex:
            futs = []
            for ns_ip in chunk:
                def attempt(ip=ns_ip):
                    if RESOLVER_FAIL_COUNT[ip] >= RESOLVER_FAIL_THRESHOLD or ip in QUARANTINED:
                        if PRINT_VERBOSE_ERRORS:
                            print(f"[SKIP] 解析器 {ip} 已隔离/失败阈值达到，跳过")
                        return []
                    r = make_resolver(False, ip)
                    local: Set[str] = set()
                    # UDP→TCP fallback，失败计数
                    for k in range(RETRIES_PER_RESOLVER):
                        ips = query_a_once_with_tcp_fallback(r, domain, f"{ip}#{k+1}")
                        if ips:
                            local.update(ips)
                    if local:
                        RESOLVER_FAIL_COUNT[ip] = 0
                    else:
                        RESOLVER_FAIL_COUNT[ip] += 1
                        if RESOLVER_FAIL_COUNT[ip] >= RESOLVER_FAIL_THRESHOLD:
                            QUARANTINED.add(ip)
                            if PRINT_VERBOSE_ERRORS:
                                print(f"[QUARANTINE] 隔离解析器 {ip}（连续失败 {RESOLVER_FAIL_COUNT[ip]} 次）")
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

        time.sleep(SLEEP_BETWEEN_WAVES)
    return sorted(collected)

def resolve_domain_multi_rounds(domain: str, resolvers: List[str]) -> List[str]:
    """多轮采样：系统DNS + 公共DNS池（每轮旋转起点），累积结果。"""
    collected: Set[str] = set()
    for round_idx in range(SAMPLES_PER_DOMAIN):
        sys_ips = resolve_with_system(domain)
        if sys_ips:
            collected.update(sys_ips)
        if resolvers:
            start_idx = (round_idx * RESOLVERS_PER_WAVE) % len(resolvers)
            pool_ips = resolve_with_pool_round(domain, resolvers, start_idx=start_idx)
            if pool_ips:
                collected.update(pool_ips)
        time.sleep(SLEEP_BETWEEN_ROUNDS)
    return sorted(collected)

# ================== 主流程 ==================

def main() -> None:
    domains = load_domains()
    resolvers = load_resolvers()

    if not domains:
        print("[INFO] 没有待解析的域名。仍会写入空 ips.txt。")
        IPS_FILE.write_text("", encoding="utf-8")
        return

    # 解析器预检
    if ENABLE_PREFLIGHT:
        resolvers = preflight_filter(resolvers)

    print(f"[INFO] 域名数量：{len(domains)}")
    print(f"[INFO] 解析器池（健康）：{len(resolvers)} 个")
    print(f"[INFO] 采样轮次：{SAMPLES_PER_DOMAIN}；每轮波次：{WAVES_PER_ROUND}；每波解析器：{RESOLVERS_PER_WAVE}")
    print(f"[INFO] 并发上限：{MAX_WORKERS}；每解析器重试：{RETRIES_PER_RESOLVER}")
    print(f"[INFO] 降速：波次间 {SLEEP_BETWEEN_WAVES}s；轮次间 {SLEEP_BETWEEN_ROUNDS}s；单查询抖动 {JITTER_PER_QUERY[0]}~{JITTER_PER_QUERY[1]}s")

    all_ips: Set[str] = set()

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

    text = "\n".join(sorted(all_ips))
    if text:
        text += "\n"
    IPS_FILE.write_text(text, encoding="utf-8")
    print(f"\n[SAVED] 已写入 {IPS_FILE.resolve()} （{len(all_ips)} 个 IPv4）")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL-GUARDED] 未预期异常: {type(e).__name__} - {e}")
        try:
            IPS_FILE.write_text("", encoding="utf-8")
        finally:
            sys.exit(0)
