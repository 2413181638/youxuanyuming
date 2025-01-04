import requests
import re
from bs4 import BeautifulSoup
import os

def get_ip_list(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text.strip().split('\n')

def get_cloudflare_zone(api_token):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    response = requests.get('https://api.cloudflare.com/client/v4/zones', headers=headers)
    response.raise_for_status()
    zones = response.json().get('result', [])
    if not zones:
        raise Exception("No zones found")
    return zones[0]['id'], zones[0]['name']

def delete_existing_dns_records(api_token, zone_id, subdomain, domain):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    while True:
        response = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', headers=headers)
        response.raise_for_status()
        records = response.json().get('result', [])
        if not records:
            break
        for record in records:
            delete_response = requests.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record["id"]}', headers=headers)
            delete_response.raise_for_status()
            print(f"Del {subdomain}:{record['id']}")

def update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    for ip in ip_list:
        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": 1,
            "proxied": False
        }
        response = requests.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', json=data, headers=headers)
        if response.status_code == 200:
            print(f"Add {subdomain}:{ip}")
        else:
            print(f"Failed to add A record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")

def get_ip_list(url):
    """
    根据 URL 动态解析 IP 地址列表，支持 TXT、HTML、JSON 三种格式。
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'  # IPv4 地址正则

        # 处理纯文本内容
        if 'text/plain' in content_type:
            return list(set(re.findall(ip_pattern, response.text)))

        # 处理 HTML 内容
        elif 'text/html' in content_type:
            soup = BeautifulSoup(response.text, 'html.parser')
            text_content = soup.get_text()  # 获取纯文本内容
            return list(set(re.findall(ip_pattern, text_content)))

        # 处理 JSON 数据
        elif 'application/json' in content_type:
            json_data = response.json()
            json_text = str(json_data)  # 将 JSON 转为字符串
            return list(set(re.findall(ip_pattern, json_text)))

        # 其他内容类型无法解析
        else:
            print(f"无法解析的内容类型：{content_type}")
            return []

    except Exception as e:
        print(f"解析 {url} 时出错: {e}")
        return []

# 示例使用
if __name__ == "__main__":
    api_token = os.getenv('CF_API_TOKEN')

    # 示例URL和子域名对应的IP列表
    subdomain_ip_mapping = {
        'xiaoqi111': 'https://ipdb.030101.xyz/api/bestcf.txt',  
        'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/ip.txt', 
        'xiaoqi222': 'https://addressesapi.090227.xyz/CloudFlareYes',
        'xiaoqi333': 'https://ip.164746.xyz/ipTop10.html',
        'xiaoqi444': 'https://raw.githubusercontent.com/jc-lw/youxuanyuming/refs/heads/main/ip.txt'
    }

    try:
        # 获取Cloudflare域区ID和域名
        zone_id, domain = get_cloudflare_zone(api_token)

        for subdomain, url in subdomain_ip_mapping.items():
            # 获取IP列表
            ip_list = get_ip_list(url)
            print(f"{subdomain}: 提取到 {len(ip_list)} 个 IP 地址: {ip_list}")

            # 删除现有的DNS记录
            delete_existing_dns_records(api_token, zone_id, subdomain, domain)

            # 更新Cloudflare DNS记录
            update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain)

    except Exception as e:
        print(f"Error: {e}")
