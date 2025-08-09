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
    return bool(re.match(ip_pattern, ip))

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
        # 截取前 max_ips 个
        ip_list = ip_list[:max_ips]
        return ip_list
    except Exception as e:
        print(f"Error fetching IPs from {url}: {e}")
        return []

def update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain, ttl=300):
    """
    批量更新 Cloudflare DNS 记录，使用并发请求，并限制速率。ttl单位为秒（5分钟=300秒）。
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
            response = request_with_retry('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers=headers, json=data)
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

async def main():
    """
    主函数，获取 IP 并更新 Cloudflare DNS，每个子域名只用前20个 IP，ttl=5分钟
    """
    api_token = os.getenv('CF_API_TOKEN')
    subdomain_ip_mapping = {
        'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ip.txt',
        'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/nodie.txt',
        'proxy': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/proxy.txt',
        'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cfip.txt',
        #'bestcf': 'https://ipdb.030101.xyz/api/bestcf.txt',
        'cm': 'https://addressesapi.090227.xyz/CloudFlareYes',
        'cmcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cmcc.txt',
        'cucc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/cucc.txt',
        'ctcc': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/main/ctcc.txt',
    }

    zone_id, domain = get_cloudflare_zone(api_token)
    if not zone_id or not domain:
        print("Cloudflare Zone retrieval failed")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for subdomain, url in subdomain_ip_mapping.items():
            if is_timeout():
                break
            # 只取每个子域名前20个IP
            ip_list = await asyncio.get_event_loop().run_in_executor(executor, get_ip_list, url, 20)
            if ip_list:
                delete_existing_dns_records(api_token, zone_id, subdomain, domain)
                update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain, ttl=300)
            else:
                print(f"No IPs found for {subdomain}.{domain} from {url}")

if __name__ == "__main__":
    asyncio.run(main())
