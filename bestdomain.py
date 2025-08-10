#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
稳定的 Cloudflare DNS 批量更新脚本（GitHub Actions + 本地运行通用）
- 使用 CF_API_TOKEN（从环境变量读取，适合 GitHub Secrets）
- 可选 CF_ZONE_ID（若你在 Secrets 存了 zone id，优先使用）
- 会翻页删除旧记录 / 再按配置创建新记录
"""

import os
import re
import time
import sys
import requests
import concurrent.futures
from typing import List, Optional

# ---------- 环境与 Token 检查 ----------
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
DOMAIN = os.getenv("DOMAIN") or "yangmie.online"

if "GITHUB_ACTIONS" in os.environ:
    print("[INFO] 检测到 GitHub Actions 环境")
else:
    print("[INFO] 本地运行")

if not CF_API_TOKEN:
    print("ERROR: 没有检测到 CF_API_TOKEN 环境变量。")
    print(" - 如果在 GitHub Actions 运行，请确认 workflow 的 env 里有：")
    print("     CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}")
    print(" - 如果本地运行，请先执行：")
    print("     export CF_API_TOKEN=你的token")
    sys.exit(1)

# ---------- 配置区 ----------
TIMEOUT = 10
MAX_RETRIES = 5
BACKOFF_BASE = 2
PER_PAGE = 100
RATE_LIMIT_DELAY = 1

SUBDOMAIN_IP_MAPPING = {
    'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ip.txt',
    'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/nodie.txt',
    'proxy': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/proxy.txt',
    'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cfip.txt',
    'cmcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cmcc.txt',
    'cucc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cucc.txt',
    'ctcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ctcc.txt',
}

SUBDOMAIN_CNAME_MAPPING = {
    'asiacdn': 'cdn.2020111.xyz',
    'west': 'cloudflare.182682.xyz',
    '1000ip': 'freeyx.cloudflare88.eu.org',
    '87cf': 'cf.877774.xyz',
    '87ctcc': 'ct.877774.xyz',
    '87cmcc': 'cmcc.877774.xyz',
    '87cucc': 'cu.877774.xyz',
    '87asia': 'asia.877774.xyz',
    '87eu': 'eur.877774.xyz',
    '87na': 'na.877774.xyz',
    'cm': 'cf.090227.xyz',
}

BASE_URL = "https://api.cloudflare.com/client/v4"
HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}

# ---------- 工具 ----------
def fail(msg: str):
    print(f"[ERROR] {msg}")
    sys.exit(1)

def request_with_retry(method: str, url: str, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as e:
            wait = BACKOFF_BASE ** attempt
            print(f"[{attempt}/{MAX_RETRIES}] 请求异常: {e} -> 等待 {wait}s 重试")
            time.sleep(wait)
            continue

        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            wait = int(ra) if ra and ra.isdigit() else (BACKOFF_BASE ** attempt)
            print(f"[{attempt}/{MAX_RETRIES}] 429 Too Many Requests, 等待 {wait}s")
            time.sleep(wait)
            continue

        if 500 <= resp.status_code < 600:
            wait = BACKOFF_BASE ** attempt
            print(f"[{attempt}/{MAX_RETRIES}] 服务端错误 {resp.status_code}, 等待 {wait}s 重试")
            time.sleep(wait)
            continue

        try:
            j = resp.json()
        except ValueError:
            j = None
        return resp, j

    raise RuntimeError(f"请求重试失败: {method} {url}")

def is_valid_ip(ip: str) -> bool:
    parts = ip.strip().split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def is_valid_hostname(host: str) -> bool:
    host = host.strip().strip('.')
    pattern = r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    return re.match(pattern, host) is not None

# ---------- Cloudflare API ----------
def get_zone_id(domain: Optional[str]) -> Optional[str]:
    if CF_ZONE_ID:
        print("[INFO] 使用 CF_ZONE_ID 环境变量")
        return CF_ZONE_ID

    if domain:
        resp, j = request_with_retry("GET", f"{BASE_URL}/zones?name={domain}")
        if j and j.get("success") and j.get("result"):
            zid = j["result"][0]["id"]
            print(f"[INFO] 找到 zone {domain} -> {zid}")
            return zid

    resp, j = request_with_retry("GET", f"{BASE_URL}/zones?page=1&per_page=50")
    if j and j.get("success") and j.get("result") and len(j["result"]) == 1:
        zid = j["result"][0]["id"]
        print(f"[INFO] Token 仅可见一个 zone，使用 {zid}")
        return zid

    return None

def list_dns_records(zone_id: str, rtype: Optional[str] = None, name: Optional[str] = None) -> List[dict]:
    out, page = [], 1
    while True:
        url = f"{BASE_URL}/zones/{zone_id}/dns_records?page={page}&per_page={PER_PAGE}"
        if rtype: url += f"&type={rtype}"
        if name: url += f"&name={name}"
        resp, j = request_with_retry("GET", url)
        if not j or not j.get("success"): break
        out.extend(j.get("result", []))
        if page >= j.get("result_info", {}).get("total_pages", 1): break
        page += 1
    return out

def delete_all_matching(zone_id: str, name: str, rtype: str) -> int:
    records = list_dns_records(zone_id, rtype=rtype, name=name)
    for rec in records:
        request_with_retry("DELETE", f"{BASE_URL}/zones/{zone_id}/dns_records/{rec['id']}")
        time.sleep(0.2)
    return len(records)

def create_dns_record(zone_id: str, rtype: str, name: str, content: str, ttl: int = 1, proxied: bool = False):
    data = {"type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied}
    resp, j = request_with_retry("POST", f"{BASE_URL}/zones/{zone_id}/dns_records", json=data)
    if j and not j.get("success"):
        err_codes = [e.get("code") for e in j.get("errors", []) if isinstance(e, dict)]
        if any(c in (81057, 81058) for c in err_codes):
            existing = list_dns_records(zone_id, rtype, name)
            if existing:
                rec_id = existing[0]["id"]
                request_with_retry("PUT", f"{BASE_URL}/zones/{zone_id}/dns_records/{rec_id}", json=data)

# ---------- IP 获取 ----------
def get_ip_list(url: str, max_ips: int = 30) -> List[str]:
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        ips = []
        for line in resp.text.splitlines():
            if is_valid_ip(line.strip()):
                ips.append(line.strip())
        return list(dict.fromkeys(ips))[:max_ips]
    except Exception as e:
        print(f"[WARN] 获取 IP 失败 {url}: {e}")
        return []

# ---------- 主流程 ----------
def main():
    print(f"[INFO] 启动脚本，DOMAIN = {DOMAIN}")
    zone_id = get_zone_id(DOMAIN)
    if not zone_id:
        fail("无法确定 zone_id，请检查 DOMAIN 或 CF_ZONE_ID 设置")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(get_ip_list, url, 20): sub for sub, url in SUBDOMAIN_IP_MAPPING.items()}
        for fut in concurrent.futures.as_completed(futures):
            sub = futures[fut]
            ip_list = fut.result()
            full_name = f"{sub}.{DOMAIN}" if sub != "@" else DOMAIN
            if not ip_list:
                print(f"[WARN] {full_name} 没有可用 IP，跳过")
                continue
            delete_all_matching(zone_id, full_name, "A")
            for ip in ip_list:
                create_dns_record(zone_id, "A", full_name, ip)

    for sub, target in SUBDOMAIN_CNAME_MAPPING.items():
        full_name = f"{sub}.{DOMAIN}" if sub != "@" else DOMAIN
        if not is_valid_hostname(target): continue
        delete_all_matching(zone_id, full_name, "CNAME")
        delete_all_matching(zone_id, full_name, "A")
        create_dns_record(zone_id, "CNAME", full_name, target)

    print("[INFO] 所有操作完成")

if __name__ == "__main__":
    main()
