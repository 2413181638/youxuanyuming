# -*- coding: utf-8 -*-
"""
IPv4 采集脚本（支持 200+ DNS 解析池）
- 域名来源：优先读取 domains.txt（每行一个），否则用代码内 DOMAINS
- 解析器来源：优先读取 dns_servers.txt（每行一个IPv4，建议>=200），否则用内置公共DNS兜底
- 策略：系统DNS（可重试） -> 公共DNS池分波并发查询（命中即停当前域名）
- 异常：全部打印到日志（包含解析器IP/异常类型），但不影响整体流程
- 写入：等所有解析完成后，合并去重排序，一次性覆盖写入 ips.txt（每次运行都会写）
"""

from __future__ import annotations
import sys
import os
import ipaddress
import random
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

# 依赖：dnspython
try:
    import dns.resolver
    import dns.exception
except ModuleNotFoundError:
    print("缺少 dnspython，请先: pip install dnspython")
    sys.exit(0)  # 不把CI判失败

# =============== 可调参数 ===============

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

# 若不存在 dns_servers.txt，则使用这份兜底池（建议提供文件扩充到 200+）
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
    # Level3 (历史常见)
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # 国内常见（可用性受环境影响）
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29",
    "180.76.76.76",
    "1.2.4.8", "210.2.4.8",
]

# 查询与并发参数
PER_QUERY_TIMEOUT = 2.0        # 单次查询超时
PER_QUERY_LIFETIME = 3.0       # 单次查询生命周期
RETRIES_PER_RESOLVER = 2       # 每个解析器的重试次数
SYSTEM_TRIES = 2               # 系统DNS尝试次数
MAX_WORKERS = min(32, (os.cpu_count() or 2) * 4)
RESOLVERS_PER_WAVE = 24        # 每波并发解析器数量
MAX_WAVES_PER_DOMAIN = 20      # 每域名最多多少波（≈ 24*20=480 解析器）

# 文件
DOMAINS_FILE = Path("domains.txt")
RESOLVERS_FILE = Path("dns_servers.txt")
IPS_FILE = Path("ips.txt")

# 日志
PRINT_VERBOSE_ERRORS = True    # 打印每个解析器的异常详情


# =============== 工具函数 ===============

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
    random.shuffle(valid)  # 打散避免总命中同一批
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
    return r

def query_a_once(resolver: dns.resolver.Resolver, domain: str, tag: str) -> List[str]:
    ips: List[str] = []
    try:
        answers = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if answers:
            for r in answers:
                ip = getattr(r, "address", "")
                if ip and is_ipv4(ip):
                    ips.append(ip)
    except Exception as e:
        if PRINT_VERBOSE_ERRORS:
            print(f"[ERROR] {domain} via {tag} 失败: {type(e).__name__} - {e}")
    return ips

def resolve_with_system(domain: str) -> List[str]:
    collected: Set[str] = set()
    sys_resolver = make_resolver(True)
    for i in range(SYSTEM_TRIES):
        ips = query_a_once(sys_resolver, domain, f"system#{i+1}")
        if ips:
            collected.update(ips); break
    return sorted(collected)

def resolve_with_pool(domain: str, pool: List[str]) -> List[str]:
    """解析器池分波并发；命中即停当前域名。"""
    if not pool:
        return []
    collected: Set[str] = set()
    total = len(pool)
    waves = min(MAX_WAVES_PER_DOMAIN, (total + RESOLVERS_PER_WAVE - 1) // RESOLVERS_PER_WAVE)

    for wave in range(waves):
        start = wave * RESOLVERS_PER_WAVE
        chunk = pool[start:start + RESOLVERS_PER_WAVE]
        if not chunk:
            break

        with ThreadPoolExecutor(max_workers=min(len(chunk), MAX_WORKERS)) as ex:
            futs = []
            for ns_ip in chunk:
                def attempt(ip=ns_ip):
                    r = make_resolver(False, ip)
                    for k in range(RETRIES_PER_RESOLVER):
                        ips = query_a_once(r, domain, f"{ip}#{k+1}")
                        if ips:
                            return ips
                    return []
                futs.append(ex.submit(attempt))

            hit = False
            for fut in as_completed(futs):
                try:
                    ips = fut.result()
                except Exception as e:
                    print(f"[FATAL] {domain} 解析器线程异常: {type(e).__name__} - {e}")
                    ips = []
                if ips:
                    collected.update(ips)
                    hit = True
            if hit:
                break  # 这一波有命中就停止继续浪费解析器

    return sorted(collected)

def resolve_one(domain: str, resolvers: List[str]) -> List[str]:
    ips = resolve_with_system(domain)
    if ips:
        return ips
    return resolve_with_pool(domain, resolvers)


# =============== 主流程 ===============

def main() -> None:
    domains = load_domains()
    resolvers = load_resolvers()

    if not domains:
        print("[INFO] 没有待解析的域名。仍会写入空 ips.txt。")
        IPS_FILE.write_text("", encoding="utf-8")
        return

    print(f"[INFO] 域名数量：{len(domains)}")
    print(f"[INFO] 解析器池：{len(resolvers)} 个（建议 >= 200）")
    print(f"[INFO] 并发上限：{MAX_WORKERS}；每波解析器：{RESOLVERS_PER_WAVE}；每解析器重试：{RETRIES_PER_RESOLVER}")

    all_ips: Set[str] = set()

    # 域名级并发
    with ThreadPoolExecutor(max_workers=min(len(domains), MAX_WORKERS)) as ex:
        future_map = {ex.submit(resolve_one, d, resolvers): d for d in domains}
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

    # —— 仅在所有解析完成后，合并去重排序，一次性覆盖写入 —— #
    new_text = "\n".join(sorted(all_ips))
    if new_text:
        new_text += "\n"
    IPS_FILE.write_text(new_text, encoding="utf-8")
    print(f"\n[SAVED] 已写入 {IPS_FILE.resolve()} （{len(all_ips)} 个 IPv4）")

    # 始终 0 退出，保证工作流不中断
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
