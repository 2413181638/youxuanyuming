import os
import re
import time
import asyncio
import requests
import threading
import concurrent.futures
from lxml import etree
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, Timeout

# 全局超时 & 并发配置
TIMEOUT = 10  # 单次请求超时时间
MAX_RETRIES = 3  # 请求重试次数
MAX_THREADS = 10  # 最大并发线程数
MAX_SCRIPT_RUNTIME = 300  # 最大脚本运行时间（秒）
RATE_LIMIT_BATCH = 10  # 每批次处理 10 个请求
RATE_LIMIT_DELAY = 1   # 每批次后暂停 1 秒

# 统一使用 Cloudflare 的“自动 TTL”
AUTO_TTL = 1

# 记录脚本启动时间
script_start_time = time.time()

def is_timeout():
    """检查脚本是否超时"""
    return time.time() - script_start_time > MAX_SCRIPT_RUNTIME

def request_with_retry(method, url, headers=None, json=None, params=None, data=None, timeout=TIMEOUT, max_retries=MAX_RETRIES):
    """
    进行 HTTP 请求，并支持重试机制。
    """
    delay = 2  # 指数退避初始延迟
    for attempt in range(max_retries):
        if is_timeout():
            raise Exception("Script execution timeout")

        try:
            response = requests.request(method, url, headers=headers, json=json, params=params, data=data, timeout=timeout)

            # 检查是否触发 Cloudflare 429 限制
            if response.status_code == 429:
                print(f"[{attempt + 1}/{max_retries}] HTTP 429 Too Many Requests. Sleeping {delay} sec...")
                time.sleep(delay)
                delay *= 2
                continue

            response.raise_for_status()
            return response
        except (RequestException, Timeout) as e:
            print(f"[{attempt + 1}/{max_retries}] Request failed: {e}. Retrying after {delay} sec...")
            time.sleep(delay)
            delay *= 2

    raise Exception(f"Request to {url} failed after {max_retries} retries.")

def is_valid_ip(ip):
    """
    验证是否为有效的 IPv4 地址。
    """
    ip_pattern = r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$'
    if not re.match(ip_pattern, ip or ""):
        return False
    parts = ip.split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

# ===== 新增：校验主机名（CNAME 目标用） =====
def is_valid_hostname(host):
    """
    粗略校验 FQDN 主机名（不含协议，不以点开头结尾）
    """
    if not host:
        return False
    host = host.strip().strip(".")
    if len(host) > 253:
        return False
    pattern = r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    return re.match(pattern, host) is not None

def get_ip_list(url, max_ips=20):
    """
    根据 URL 获取 IP 列表，支持 .txt 文件和 HTML 页面解析。只保留前 max_ips 个 IP。
    """
    try:
        response = request_with_retry('GET', url)
        ip_list = []
        if url.endswith('.txt'):
            # 处理纯文本文件，确保每行是有效 IP
            ip_list = [line.strip() for line in response.text.strip().split('\n') if is_valid_ip(line.strip())]
        else:
            # 处理 HTML 页面
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            ip_list = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            ip_list = [ip for ip in ip_list if is_valid_ip(ip)]
        # 去重 + 截取前 max_ips 个
        seen, out = set(), []
        for ip in ip_list:
            if ip not in seen:
                out.append(ip)
                seen.add(ip)
            if len(out) >= max_ips:
                break
        return out
    except Exception as e:
        print(f"Error fetching IPs from {url}: {e}")
        return []

def update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain, ttl=AUTO_TTL):
    """
    批量更新 Cloudflare DNS 记录，使用并发请求，并限制速率。ttl=1 表示自动。
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain

    def add_dns_record(ip):
        """
        添加 A 记录
        """
        if is_timeout():
            return
        if not is_valid_ip(ip):
            print(f"Skipping invalid IP for {record_name}: {ip}")
            return
        data = {"type": "A", "name": record_name, "content": ip, "ttl": ttl, "proxied": False}
        try:
            request_with_retry('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers=headers, json=data)
            print(f"Added {record_name} -> {ip}")
        except Exception as e:
            print(f"Failed to add {record_name} -> {ip}: {e}")

    # 分批处理 IP 列表，每 10 个请求暂停 1 秒
    for i in range(0, len(ip_list), RATE_LIMIT_BATCH):
        batch = ip_list[i:i + RATE_LIMIT_BATCH]
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            executor.map(add_dns_record, batch)
        print(f"Processed batch {i // RATE_LIMIT_BATCH + 1}, sleeping for {RATE_LIMIT_DELAY} sec...")
        time.sleep(RATE_LIMIT_DELAY)

def get_cloudflare_zone(api_token):
    """
    获取 Cloudflare 域名的 Zone ID。
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    try:
        response = request_with_retry('GET', 'https://api.cloudflare.com/client/v4/zones', headers=headers)
        zones = response.json().get('result', [])
        if zones:
            return zones[0]['id'], zones[0]['name']
    except Exception as e:
        print(f"Error fetching Cloudflare zones: {e}")
    return None, None

def delete_existing_dns_records(api_token, zone_id, subdomain, domain):
    """
    批量删除 Cloudflare 现有 A 记录，减少 API 调用次数。
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain

    try:
        response = request_with_retry('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', headers=headers)
        records = response.json().get('result', [])

        if not records:
            return

        # 分批删除记录，每 10 个请求暂停 1 秒
        for i in range(0, len(records), RATE_LIMIT_BATCH):
            batch = records[i:i + RATE_LIMIT_BATCH]
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                executor.map(lambda rec: request_with_retry('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec["id"]}', headers=headers), batch)
            print(f"Deleted batch {i // RATE_LIMIT_BATCH + 1} of DNS records for {record_name}, sleeping for {RATE_LIMIT_DELAY} sec...")
            time.sleep(RATE_LIMIT_DELAY)

        print(f"Deleted existing DNS records for {record_name}")

    except Exception as e:
        print(f"Error deleting DNS records for {record_name}: {e}")

# ===== 新增：查询现有 CNAME =====
def get_existing_cname_record(api_token, zone_id, subdomain, domain):
    """
    查询子域当前是否已有 CNAME 记录：
    - 返回 dict（Cloudflare record）或 None
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain
    try:
        resp = request_with_retry(
            'GET',
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=CNAME&name={record_name}',
            headers=headers
        )
        records = resp.json().get('result', []) or []
        return records[0] if records else None
    except Exception as e:
        print(f"Error querying CNAME for {record_name}: {e}")
        return None

# ===== 新增：删除 CNAME 记录（并可选清理 A 以避免冲突） =====
def delete_existing_cname_records(api_token, zone_id, subdomain, domain, also_delete_A=True):
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain
    try:
        # 删 CNAME
        resp = request_with_retry('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=CNAME&name={record_name}', headers=headers)
        cname_records = resp.json().get('result', [])
        for i in range(0, len(cname_records), RATE_LIMIT_BATCH):
            batch = cname_records[i:i + RATE_LIMIT_BATCH]
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                executor.map(lambda rec: request_with_retry('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec["id"]}', headers=headers), batch)
            print(f"Deleted CNAME batch {i // RATE_LIMIT_BATCH + 1} for {record_name}")
            time.sleep(RATE_LIMIT_DELAY)
        if cname_records:
            print(f"Deleted existing CNAME for {record_name}")

        # 为避免“同名 CNAME 与 A 冲突”，可选再删 A
        if also_delete_A:
            delete_existing_dns_records(api_token, zone_id, subdomain, domain)

    except Exception as e:
        print(f"Error deleting CNAME for {record_name}: {e}")

# ===== 新增：创建/更新 CNAME 记录（TTL 自动） =====
def upsert_cname_record(api_token, zone_id, subdomain, domain, target, ttl=AUTO_TTL, proxied=False):
    """
    为 subdomain 创建单条 CNAME：name -> target
    注意：DNS 规范同名只能有 1 条 CNAME，且不可与 A/AAAA 并存。
    """
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain
    target = target.strip().strip(".")
    if not is_valid_hostname(target):
        print(f"Invalid CNAME target for {record_name}: {target}")
        return
    data = {"type": "CNAME", "name": record_name, "content": target, "ttl": ttl, "proxied": proxied}
    try:
        request_with_retry('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers=headers, json=data)
        print(f"Added CNAME {record_name} -> {target}")
    except Exception as e:
        print(f"Failed to add CNAME {record_name} -> {target}: {e}")

# ===== 新增：只更新 TTL 的 PATCH =====
def patch_dns_record_ttl(api_token, zone_id, record_id, ttl=AUTO_TTL):
    headers = {'Authorization': f'Bearer {api_token}', 'Content-Type': 'application/json'}
    try:
        request_with_retry(
            'PATCH',
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}',
            headers=headers,
            json={"ttl": ttl}
        )
        print(f"[PATCH] TTL updated to {ttl} for record {record_id}")
    except Exception as e:
        print(f"[WARN] Patch TTL failed for {record_id}: {e}")

async def main():
    """
    主函数：
    - A 记录：保留原流程，TTL 统一自动
    - CNAME：先查，有且目标一致则只在 TTL≠自动时 PATCH；否则按需更新/创建，TTL 自动
    """
    api_token = os.getenv('CF_API_TOKEN')
    subdomain_ip_mapping = {
        'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ip.txt',
        'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/nodie.txt',
        'proxy': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/proxy.txt',
        'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cfip.txt',
        'cmcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cmcc.txt',
        'cucc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cucc.txt',
        'ctcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ctcc.txt',
    }

    # CNAME 列表（你只需填别人域名的目标）
    subdomain_cname_mapping = {
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
    CNAME_TTL = AUTO_TTL
    CNAME_PROXIED = False  # 如需橙云，可改 True

    zone_id, domain = get_cloudflare_zone(api_token)
    if not zone_id or not domain:
        print("Cloudflare Zone retrieval failed")
        return

    # ===== 先按原逻辑更新 A 记录（TTL=自动） =====
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for subdomain, url in subdomain_ip_mapping.items():
            if is_timeout():
                break
            ip_list = await asyncio.get_event_loop().run_in_executor(executor, get_ip_list, url, 20)
            if ip_list:
                delete_existing_dns_records(api_token, zone_id, subdomain, domain)
                update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain, ttl=AUTO_TTL)
            else:
                print(f"No IPs found for {subdomain}.{domain} from {url}")

    # ===== 再单独处理 CNAME 列表（每个子域 1 条，TTL=自动）=====
    for subdomain, target in subdomain_cname_mapping.items():
        if is_timeout():
            break

        record_name = f"{subdomain}.{domain}" if subdomain != '@' else domain
        target_norm = (target or "").strip().strip(".").lower()
        if not is_valid_hostname(target_norm):
            print(f"[INFO] Skip invalid CNAME target for {record_name}: {target}")
            continue

        existing = get_existing_cname_record(api_token, zone_id, subdomain, domain)

        if existing:
            existing_target = (existing.get('content') or "").strip().strip(".").lower()
            existing_ttl = existing.get('ttl')
            if existing_target == target_norm:
                # 仅检查 TTL；不是自动就改成自动
                if existing_ttl != AUTO_TTL:
                    print(f"[FIX] TTL not auto for {record_name} (ttl={existing_ttl}) -> set to AUTO")
                    patch_dns_record_ttl(api_token, zone_id, existing.get('id'), ttl=AUTO_TTL)
                else:
                    print(f"[SKIP] CNAME unchanged & TTL auto: {record_name} -> {existing.get('content')}")
                continue
            else:
                # 目标不同 —— 仅删除旧 CNAME，再创建新 CNAME（不动 A）
                print(f"[UPDATE] CNAME target changed for {record_name}: {existing.get('content')} -> {target}")
                delete_existing_cname_records(api_token, zone_id, subdomain, domain, also_delete_A=False)
                upsert_cname_record(api_token, zone_id, subdomain, domain, target, ttl=CNAME_TTL, proxied=CNAME_PROXIED)
        else:
            # 不存在 —— 先删同名 A，避免冲突，再创建 CNAME（TTL 自动）
            print(f"[CREATE] No existing CNAME for {record_name}, creating -> {target}")
            delete_existing_dns_records(api_token, zone_id, subdomain, domain)  # 清理 A
            upsert_cname_record(api_token, zone_id, subdomain, domain, target, ttl=CNAME_TTL, proxied=CNAME_PROXIED)

if __name__ == "__main__":
    asyncio.run(main())
