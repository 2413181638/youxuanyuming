#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
稳定的 Cloudflare DNS 批量更新脚本
- 使用 CF_API_TOKEN（从环境变量读取，适合 GitHub Secrets）
- 可选 CF_ZONE_ID（若你在 Secrets 存了 zone id，优先使用）
- 会翻页删除旧记录 / 再按配置创建新记录
"""

import os
import re
import time
import sys
import json
import requests
import concurrent.futures
from typing import List, Optional

# ---------- 配置区（可直接改这里，或由外部配置替换） ----------
DOMAIN = os.getenv("DOMAIN") or "yangmie.online"   # 主域
CF_API_TOKEN = os.getenv("CF_API_TOKEN")           # **必须** 从 GitHub Secrets 注入
CF_ZONE_ID = os.getenv("CF_ZONE_ID")               # 可选：若有可直接用，避免查 zone
TIMEOUT = 10
MAX_RETRIES = 5
BACKOFF_BASE = 2
PER_PAGE = 100
RATE_LIMIT_DELAY = 1
# 原始 IP 来源（你的原始配置）
SUBDOMAIN_IP_MAPPING = {
    'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ip.txt',
    'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/nodie.txt',
    'proxy': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/proxy.txt',
    'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cfip.txt',
    'cmcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cmcc.txt',
    'cucc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cucc.txt',
    'ctcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ctcc.txt',
}

# CNAME 配置（你的原配置）
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
# ------------------------------------------------------------------

BASE_URL = "https://api.cloudflare.com/client/v4"
HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}


# ---------- 工具函数 ----------
def fail(msg: str):
    print("ERROR:", msg)
    sys.exit(1)


def request_with_retry(method: str, url: str, **kwargs):
    """
    包含 429 / 5xx 的重试，返回 (response, json_or_none)
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as e:
            wait = BACKOFF_BASE ** attempt
            print(f"[{attempt}/{MAX_RETRIES}] 请求异常: {e} -> 等待 {wait}s 重试")
            time.sleep(wait)
            continue

        # 处理 429（尊重 Retry-After）
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            wait = int(ra) if ra and ra.isdigit() else (BACKOFF_BASE ** attempt)
            print(f"[{attempt}/{MAX_RETRIES}] 429 Too Many Requests, 等待 {wait}s")
            time.sleep(wait)
            continue

        # 5xx 重试
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
    if not ip:
        return False
    parts = ip.strip().split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def is_valid_hostname(host: str) -> bool:
    if not host:
        return False
    host = host.strip().strip('.')
    if len(host) > 253:
        return False
    pattern = r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    return re.match(pattern, host) is not None


# ---------- Cloudflare Zone / DNS 操作 ----------
def get_zone_id(domain: Optional[str]) -> Optional[str]:
    """
    优先返回 CF_ZONE_ID（如果有），否则按 domain 精确查询 zone。
    如果 token 仅允许单个 zone 且没有 domain，尝试列出 zones 并在只有 1 个时返回。
    """
    if not CF_API_TOKEN:
        fail("CF_API_TOKEN 未设置，请在 GitHub Secrets 中添加 CF_API_TOKEN。")

    if CF_ZONE_ID:
        # 验证可选（不暴露 token）
        print("使用环境变量中的 CF_ZONE_ID（已省略具体值）")
        if domain:
            # 尝试查询该 zone 信息以校验（但如果 token 没权限，这步可能报错）
            resp, j = request_with_retry("GET", f"{BASE_URL}/zones/{CF_ZONE_ID}")
            if j and j.get("success"):
                zone_name = j["result"]["name"]
                if zone_name != domain:
                    print(f"警告：CF_ZONE_ID 对应 zone 为 {zone_name}，与你指定的 DOMAIN {domain} 不同")
            else:
                print(f"无法验证 CF_ZONE_ID：{j}")
        return CF_ZONE_ID

    if domain:
        url = f"{BASE_URL}/zones?name={domain}"
        resp, j = request_with_retry("GET", url)
        if j and j.get("success") and j.get("result"):
            zid = j["result"][0]["id"]
            print(f"找到 zone {domain} -> {zid}")
            return zid
        else:
            print(f"按 domain 查询 zone 失败：{j}")

    # 回退：列出 token 可见的 zones，如果只有一个就返回
    resp, j = request_with_retry("GET", f"{BASE_URL}/zones?page=1&per_page=50")
    if j and j.get("success") and j.get("result"):
        if len(j["result"]) == 1:
            print("Token 仅可见一个 zone，使用该 zone")
            return j["result"][0]["id"]
        else:
            print("Token 可见多个 zone，建议设置 DOMAIN 或 CF_ZONE_ID。可见 zone：", [z["name"] for z in j["result"]])
            return None
    print("无法获取 zone id:", j)
    return None


def list_dns_records(zone_id: str, rtype: Optional[str] = None, name: Optional[str] = None) -> List[dict]:
    """翻页获取匹配的 DNS 记录"""
    out = []
    page = 1
    while True:
        url = f"{BASE_URL}/zones/{zone_id}/dns_records?page={page}&per_page={PER_PAGE}"
        if rtype:
            url += f"&type={rtype}"
        if name:
            url += f"&name={name}"
        resp, j = request_with_retry("GET", url)
        if not j or not j.get("success"):
            print("list_dns_records 返回:", j)
            break
        res = j.get("result", [])
        out.extend(res)
        info = j.get("result_info", {})
        if page >= info.get("total_pages", 1):
            break
        page += 1
    return out


def delete_dns_record(zone_id: str, rec_id: str, name: str):
    url = f"{BASE_URL}/zones/{zone_id}/dns_records/{rec_id}"
    resp, j = request_with_retry("DELETE", url)
    print(f"DELETE {name} id={rec_id} ->", j)
    return j


def delete_all_matching(zone_id: str, name: str, rtype: str):
    """翻页删除 name + type 匹配的所有记录"""
    records = list_dns_records(zone_id, rtype=rtype, name=name)
    if not records:
        return 0
    cnt = 0
    for rec in records:
        delete_dns_record(zone_id, rec["id"], rec.get("name"))
        cnt += 1
        time.sleep(0.2)
    return cnt


def create_dns_record(zone_id: str, rtype: str, name: str, content: str, ttl: int = 1, proxied: bool = False):
    url = f"{BASE_URL}/zones/{zone_id}/dns_records"
    data = {"type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied}
    resp, j = request_with_retry("POST", url, json=data)
    print(f"POST {rtype} {name} -> {content} =>", j)
    # 若创建失败且是“已存在”错误，尝试更新第一个匹配的记录
    if j and not j.get("success"):
        err_codes = [e.get("code") for e in j.get("errors", []) if isinstance(e, dict)]
        if any(c in (81057, 81058) for c in err_codes):
            existing = list_dns_records(zone_id, rtype, name)
            if existing:
                rec_id = existing[0]["id"]
                put_url = f"{BASE_URL}/zones/{zone_id}/dns_records/{rec_id}"
                resp2, j2 = request_with_retry("PUT", put_url, json=data)
                print(f"PUT 更新 {rec_id} ->", j2)
                return j2
    return j


# ---------- 获取远程 IP 列表 ----------
def get_ip_list(url: str, max_ips: int = 20) -> List[str]:
    try:
        resp, j = request_with_retry("GET", url)  # 不带 auth header 也可以，因为 HEADERS 中有 token — token 对外域请求不会影响
        text = resp.text or ""
        ip_list = []
        if url.endswith(".txt"):
            for line in text.splitlines():
                line = line.strip()
                if is_valid_ip(line):
                    ip_list.append(line)
        else:
            # 从页面抓 IP
            found = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            for ip in found:
                if is_valid_ip(ip):
                    ip_list.append(ip)
        # 去重 + 截断
        out = []
        seen = set()
        for ip in ip_list:
            if ip not in seen:
                out.append(ip)
                seen.add(ip)
            if len(out) >= max_ips:
                break
        return out
    except Exception as e:
        print("get_ip_list 失败:", e)
        return []


# ---------- 主流程 ----------
def main():
    print("启动脚本，DOMAIN =", DOMAIN)
    zone_id = get_zone_id(DOMAIN)
    if not zone_id:
        fail("无法确定 zone_id；请设置 CF_ZONE_ID 或确保 CF_API_TOKEN 有相应权限并正确设置 DOMAIN")

    # 1) 处理 A 记录（并发抓 IP）
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        future_map = {}
        for sub, url in SUBDOMAIN_IP_MAPPING.items():
            future_map[ex.submit(get_ip_list, url, 20)] = (sub, url)
        for fut in concurrent.futures.as_completed(future_map):
            sub, url = future_map[fut]
            try:
                ip_list = fut.result()
            except Exception as e:
                print(f"获取 {sub} IP 出错: {e}")
                ip_list = []
            full_name = f"{sub}.{DOMAIN}" if sub != "@" else DOMAIN
            if not ip_list:
                print(f"[WARN] 没拿到 IP 列表，跳过 {full_name}")
                continue

            print(f"[A] {full_name} -> {len(ip_list)} IP(s) 从 {url}")
            # 删除旧的 A 记录（彻底翻页删除）
            deleted = delete_all_matching(zone_id, full_name, "A")
            print(f"删除旧 A 记录数量: {deleted}, 等待同步...")
            time.sleep(3)
            # 逐个创建
            for ip in ip_list:
                if not is_valid_ip(ip):
                    print("跳过无效 IP:", ip)
                    continue
                create_dns_record(zone_id, "A", full_name, ip, ttl=1, proxied=False)
                time.sleep(0.2)
            print(f"[DONE] {full_name}")

    # 2) 处理 CNAME 列表
    for sub, target in SUBDOMAIN_CNAME_MAPPING.items():
        full_name = f"{sub}.{DOMAIN}" if sub != "@" else DOMAIN
        target_norm = (target or "").strip().strip(".")
        if not is_valid_hostname(target_norm):
            print(f"[INFO] 跳过无效 CNAME 目标: {full_name} -> {target}")
            continue

        # 删除同名 CNAME
        existing_cname = list_dns_records(zone_id, rtype="CNAME", name=full_name)
        if existing_cname:
            print(f"找到已有 CNAME（{len(existing_cname)}），删除以便创建新 CNAME")
            delete_all_matching(zone_id, full_name, "CNAME")
            time.sleep(1)

        # 为避免 CNAME 与 A 冲突，删除 A
        existing_a = list_dns_records(zone_id, rtype="A", name=full_name)
        if existing_a:
            print("删除冲突的 A 记录以创建 CNAME")
            delete_all_matching(zone_id, full_name, "A")
            time.sleep(1)

        # 创建 CNAME（若已存在会自动尝试 PUT）
        create_dns_record(zone_id, "CNAME", full_name, target_norm, ttl=1, proxied=False)
        time.sleep(0.5)

    print("所有操作完成。请到 Cloudflare Dashboard 或使用 dig 验证（示例：dig +short xiaoqi.{domain} @1.1.1.1）".format(domain=DOMAIN))


if __name__ == "__main__":
    main()
