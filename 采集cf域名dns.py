# -*- coding: utf-8 -*-
import sys
from pathlib import Path

# 依赖：dnspython
try:
    import dns.resolver
    import dns.exception
except ModuleNotFoundError:
    print("缺少 dnspython，请先 pip install dnspython")
    sys.exit(1)

# 在这里维护你的域名列表（可随时增减）
DOMAINS = [
    "cloudflare.182682.xyz",
    "bestcf.top",
    "cdn.2020111.xyz",
    "cf.0sm.com",
    "cf.090227.xyz",
    "cf.zhetengsha.eu.org",
    "cfip.1323123.xyz",
    "cnamefuckxxs.yuchen.icu",
    "cloudflare-ip.mofashi.ltd",
    "freeyx.cloudflare88.eu.org"
  
  
    # "你的域名.com",
]

# 可选：指定公共DNS作为后备（系统解析失败时）
FALLBACK_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]

def resolve_a_records(domain: str) -> list[str]:
    """解析域名的 A 记录（IPv4），返回字符串列表"""
    ips: set[str] = set()

    def query_with(resolver: dns.resolver.Resolver):
        try:
            answers = resolver.resolve(domain, "A", lifetime=3.0)
            for rdata in answers:
                ips.add(rdata.address)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass

    # 先用系统默认解析
    resolver = dns.resolver.Resolver(configure=True)
    query_with(resolver)

    # 若没解析到，则尝试后备 DNS
    if not ips:
        for ns in FALLBACK_NAMESERVERS:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [ns]
            r.timeout = 2.0
            r.lifetime = 3.0
            query_with(r)
            if ips:
                break

    return sorted(ips)

def main():
    all_ips: set[str] = set()

    for d in DOMAINS:
        ips = resolve_a_records(d)
        if ips:
            print(f"[OK] {d} -> {', '.join(ips)}")
            all_ips.update(ips)
        else:
            print(f"[WARN] {d} 未解析到 IPv4")

    # 写入根目录 ips.txt（仅 IPv4，每行一个，排序、去重）
    out_path = Path("ips.txt")
    lines = "\n".join(sorted(all_ips)) + ("\n" if all_ips else "")
    out_path.write_text(lines, encoding="utf-8")
    print(f"\n已写入 {out_path.resolve()} （{len(all_ips)} 个 IPv4）")

if __name__ == "__main__":
    main()
