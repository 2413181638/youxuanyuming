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
# 从环境变量中获取 Cloudflare API Token 和 Zone ID，如果未设置，会退出程序
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
CF_ZONE_ID = os.getenv("CF_ZONE_ID")
DOMAIN = os.getenv("DOMAIN") or "yangmie.online"  # 默认域名

# 检查当前环境是 GitHub Actions 还是本地运行
if "GITHUB_ACTIONS" in os.environ:
    print("[INFO] 检测到 GitHub Actions 环境")
else:
    print("[INFO] 本地运行")

# 如果未设置 CF_API_TOKEN，则退出程序
if not CF_API_TOKEN:
    print("ERROR: 没有检测到 CF_API_TOKEN 环境变量。")
    print(" - 如果在 GitHub Actions 运行，请确认 workflow 的 env 里有：")
    print("     CF_API_TOKEN: ${{ secrets.CF_API_TOKEN }}")
    print(" - 如果本地运行，请先执行：")
    print("     export CF_API_TOKEN=你的token")
    sys.exit(1)

# ---------- 配置区 ----------
TIMEOUT = 10  # 请求超时设置
MAX_RETRIES = 5  # 最大重试次数
BACKOFF_BASE = 2  # 重试等待基数
PER_PAGE = 100  # 每页显示记录数
RATE_LIMIT_DELAY = 1  # 限流延迟

# 各个子域名与 IP 地址文件的映射
SUBDOMAIN_IP_MAPPING = {
    'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ip.txt',
    'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/nodie.txt',
    'proxy': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/proxy.txt',
    'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cfip.txt',
    'cmcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cmcc.txt',
    'cucc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cucc.txt',
    'ctcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ctcc.txt',
}

# 各个子域名与 CNAME 的映射
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

BASE_URL = "https://api.cloudflare.com/client/v4"  # Cloudflare API 基础 URL
HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}  # 请求头

# ---------- 工具函数 ----------

# 错误退出函数
def fail(msg: str):
    print(f"[ERROR] {msg}")
    sys.exit(1)

# 带重试机制的请求函数
def request_with_retry(method: str, url: str, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # 发起请求
            resp = requests.request(method, url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as e:
            # 请求异常，进行重试
            wait = BACKOFF_BASE ** attempt
            print(f"[{attempt}/{MAX_RETRIES}] 请求异常: {e} -> 等待 {wait}s 重试")
            time.sleep(wait)
            continue

        if resp.status_code == 429:
            # 如果是限流错误，获取重试时间并等待
            ra = resp.headers.get("Retry-After")
            wait = int(ra) if ra and ra.isdigit() else (BACKOFF_BASE ** attempt)
            print(f"[{attempt}/{MAX_RETRIES}] 429 Too Many Requests, 等待 {wait}s")
            time.sleep(wait)
            continue

        if 500 <= resp.status_code < 600:
            # 如果是服务端错误，进行重试
            wait = BACKOFF_BASE ** attempt
            print(f"[{attempt}/{MAX_RETRIES}] 服务端错误 {resp.status_code}, 等待 {wait}s 重试")
            time.sleep(wait)
            continue

        try:
            # 尝试将返回内容解析为 JSON
            j = resp.json()
        except ValueError:
            j = None
        return resp, j

    # 如果所有重试都失败，则抛出异常
    raise RuntimeError(f"请求重试失败: {method} {url}")

# 判断是否是有效的 IP 地址
def is_valid_ip(ip: str) -> bool:
    parts = ip.strip().split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

# 判断是否是有效的域名
def is_valid_hostname(host: str) -> bool:
    host = host.strip().strip('.')
    pattern = r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    return re.match(pattern, host) is not None

# ---------- Cloudflare API 函数 ----------

# 获取 zone_id，若指定了 CF_ZONE_ID 环境变量则直接返回，否则通过域名查找
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

# 获取指定 zone 的 DNS 记录
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

# 删除所有匹配的 DNS 记录
def delete_all_matching(zone_id: str, name: str, rtype: str) -> int:
    records = list_dns_records(zone_id, rtype=rtype, name=name)
    for rec in records:
        request_with_retry("DELETE", f"{BASE_URL}/zones/{zone_id}/dns_records/{rec['id']}")
        time.sleep(0.2)
    return len(records)

# 创建 DNS 记录
def create_dns_record(zone_id: str, rtype: str, name: str, content: str, ttl: int = 1, proxied: bool = False):
    data = {"type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied}
    resp, j = request_with_retry("POST", f"{BASE_URL}/zones/{zone_id}/dns_records", json=data)
    if j and not j.get("success"):
        err_codes = [e.get("code") for e in j.get("errors", []) if isinstance(e, dict)]
        if any(c in (81057, 81058) for c in err_codes):
            # 如果记录已存在，则更新记录
            existing = list_dns_records(zone_id, rtype, name)
            if existing:
                rec_id = existing[0]["id"]
                request_with_retry("PUT", f"{BASE_URL}/zones/{zone_id}/dns_records/{rec_id}", json=data)

# ---------- 获取 IP 列表 ----------

# 从指定 URL 获取 IP 地址列表
def get_ip_list(url: str, max_ips: int = 30) -> List[str]:  # 修改最大 IP 数量为 30
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        ips = []
        for line in resp.text.splitlines():
            if is_valid_ip(line.strip()):
                ips.append(line.strip())
        return list(dict.fromkeys(ips))[:max_ips]  # 只取前 max_ips 个 IP
    except Exception as e:
        print(f"[WARN] 获取 IP 失败 {url}: {e}")
        return []

# ---------- 主流程 ----------

# 主函数
def main():
    print(f"[INFO] 启动脚本，DOMAIN = {DOMAIN}")
    zone_id = get_zone_id(DOMAIN)
    if not zone_id:
        fail("无法确定 zone_id，请检查 DOMAIN 或 CF_ZONE_ID 设置")

    # 使用线程池并发获取每个子域名的 IP 列表
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(get_ip_list, url, 30): sub for sub, url in SUBDOMAIN_IP_MAPPING.items()}
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

    # 创建 CNAME 记录
    for sub, target in SUBDOMAIN_CNAME_MAPPING.items():
        full_name = f"{sub}.{DOMAIN}" if sub != "@" else DOMAIN
        if not is_valid_hostname(target): continue
        delete_all_matching(zone_id, full_name, "CNAME")
        delete_all_matching(zone_id, full_name, "A")
        create_dns_record(zone_id, "CNAME", full_name, target)

    print("[INFO] 所有操作完成")

# 如果是主程序执行，调用 main 函数
if __name__ == "__main__":
    main()
