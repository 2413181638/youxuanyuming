import os
import re
import time
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
import json

# 设置全局超时
TIMEOUT = 10
# 每个子域名最大IP数量
MAX_IP_COUNT = 200

def get_ip_list(url):
    """从URL获取IP列表，支持txt和HTML"""
    if url.endswith('.txt'):
        try:
            response = requests.get(url, timeout=TIMEOUT)
            response.raise_for_status()
            ip_list = response.text.strip().split('\n')
            print(f"IP list from {url}: {ip_list}")
            return ip_list
        except RequestException as e:
            print(f"Error fetching IP list from {url}: {e}")
            return []
    else:
        print(f"URL is not a txt file, trying to parse HTML from {url}...")
        return parse_html_for_ips(url)

def parse_html_for_ips(url):
    """解析HTML提取IP地址"""
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        ip_list = []
        for item in soup.find_all(text=re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')): # 更精确的匹配方式
            ip = item.strip()
            if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip):
                ip_list.append(ip)

        if ip_list:
            print(f"Parsed IPs from {url}: {ip_list}")
            return ip_list
        else:
            print(f"No valid IP addresses found in {url}.")
            return []
    except RequestException as e:
        print(f"Error fetching or parsing HTML from {url}: {e}")
        return []

def get_cloudflare_zone(api_token):
    """获取Cloudflare区域ID和域名"""
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    try:
        response = requests.get('https://api.cloudflare.com/client/v4/zones', headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        zones = response.json().get('result', [])
        if not zones:
            raise Exception("No zones found")
        # 改进：如果找到多个zone，打印出来让用户选择
        if len(zones) > 1:
            print("找到多个Zone，请检查并选择正确的Zone ID：")
            for i, zone in enumerate(zones):
                print(f"{i+1}. ID: {zone['id']}, Name: {zone['name']}")
            # 这里可以添加让用户输入选择的逻辑
            return zones[0]['id'], zones[0]['name'] # 默认选择第一个
        return zones[0]['id'], zones[0]['name']
    except RequestException as e:
        print(f"Error fetching Cloudflare zones: {e}")
        return None, None

def delete_existing_dns_records(api_token, zone_id, subdomain, domain):
    """删除已存在的DNS记录"""
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    try:
        response = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        records = response.json().get('result', [])
        if not records:
            print(f"No existing DNS records for {record_name}, skipping delete.")
            return

        for record in records:
            delete_response = requests.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record["id"]}', headers=headers, timeout=TIMEOUT)
            delete_response.raise_for_status()
            print(f"Del {subdomain}:{record['id']} - {delete_response.status_code} {delete_response.text}")
    except RequestException as e:
        print(f"Error deleting DNS records for {record_name}: {e}")

def update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain):
    """更新Cloudflare DNS记录"""
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    ip_list = ip_list[:MAX_IP_COUNT]

    for ip in ip_list:
        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": 1,
            "proxied": False # 不使用代理
        }
        try:
            response = requests.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', json=data, headers=headers, timeout=TIMEOUT)
            print(f"Attempting to add A record for {record_name} with IP {ip}: {response.status_code} {response.text}")
            if response.status_code == 200:
                print(f"Add {subdomain}:{ip}")
            elif response.status_code == 400 and "already exists" in response.text:
                print(f"IP {ip} already exists for {record_name}. Skipping.")
            else:
                print(f"Failed to add A record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")
        except RequestException as e:
            print(f"Error updating DNS record for {record_name} with IP {ip}: {e}")

        time.sleep(1)

if __name__ == "__main__":
    api_token = os.getenv('CF_API_TOKEN')
    if not api_token:
        print("请设置CF_API_TOKEN环境变量！")
        exit(1)

    domain = os.getenv('CF_DOMAIN')
    if not domain:
        print("请设置CF_DOMAIN环境变量！")
        exit(1)
        
    subdomain_ip_mapping_json = os.getenv('SUBDOMAIN_IP_MAPPING')
    if not subdomain_ip_mapping_json:
        print("请设置SUBDOMAIN_IP_MAPPING环境变量！")
        exit(1)
    try:
        subdomain_ip_mapping = json.loads(subdomain_ip_mapping_json)
    except json.JSONDecodeError:
        print("SUBDOMAIN_IP_MAPPING环境变量格式不正确，应为JSON格式！")
        exit(1)

    try:
        zone_id, retrieved_domain = get_cloudflare_zone(api_token)

        if zone_id is None:
            raise Exception("Cloudflare Zone retrieval failed")
        
        if domain != retrieved_domain:
            raise Exception(f"环境变量中域名({domain})与Cloudflare Zone域名({retrieved_domain})不一致！")

        for subdomain, url in subdomain_ip_mapping.items():
            ip_list = get_ip_list(url)
            if not ip_list:
                print(f"No IPs found for {subdomain}. Skipping DNS update.")
                continue

            ip_list = list(set(ip_list))
            print(f"Updating {subdomain} with {len(ip_list)} IPs")

            delete_existing_dns_records(api_token, zone_id, subdomain, domain)
            update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain)
            print(f"Finished updating {subdomain}")

    except Exception as e:
        print(f"An error occurred: {e}")
