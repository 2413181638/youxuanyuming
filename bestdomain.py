import os
import re
import time
import requests
from lxml import etree
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# 设置全局超时
TIMEOUT = 10  # 设置请求超时时间为10秒

def get_ip_list(url):
    # 检查URL是否是txt文件
    if url.endswith('.txt'):
        try:
            response = requests.get(url, timeout=TIMEOUT)
            response.raise_for_status()
            ip_list = response.text.strip().split('\n')
            print(f"IP list from {url}: {ip_list}")  # 调试输出
            return ip_list
        except RequestException as e:
            print(f"Error fetching IP list from {url}: {e}")
            return []
    else:
        # 如果是非txt文件（例如HTML），解析HTML提取IP地址
        print(f"URL is not a txt file, trying to parse HTML from {url}...")
        return parse_html_for_ips(url)

def parse_html_for_ips(url):
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()

        # 尝试用BeautifulSoup解析HTML内容
        soup = BeautifulSoup(response.text, 'html.parser')
        ip_list = []

        # 提取页面中所有可能的IP（假设IP在特定标签中）
        for item in soup.find_all('a', href=True):
            ip = item.get_text().strip()
            # 正则匹配IP地址
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
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    try:
        response = requests.get('https://api.cloudflare.com/client/v4/zones', headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        zones = response.json().get('result', [])
        print(f"Zones: {zones}")  # 打印返回的所有 Zones，检查是否有你需要的 Zone
        if not zones:
            raise Exception("No zones found")
        return zones[0]['id'], zones[0]['name']
    except RequestException as e:
        print(f"Error fetching Cloudflare zones: {e}")
        return None, None

def delete_existing_dns_records(api_token, zone_id, subdomain, domain):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'
    while True:
        try:
            response = requests.get(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}', headers=headers, timeout=TIMEOUT)
            response.raise_for_status()
            print(f"Get DNS records for {record_name}: {response.status_code} {response.text}")  # 调试输出
            records = response.json().get('result', [])

            if not records:
                break

            for record in records:
                delete_response = requests.delete(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record["id"]}', headers=headers, timeout=TIMEOUT)
                delete_response.raise_for_status()
                print(f"Del {subdomain}:{record['id']} - {delete_response.status_code} {delete_response.text}")  # 调试输出

        except RequestException as e:
            print(f"Error deleting DNS records for {record_name}: {e}")
            break

def update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain, batch_size=200):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'

    # 批量处理IP，分批更新
    for i in range(0, len(ip_list), batch_size):
        batch_ips = ip_list[i:i + batch_size]

        for ip in batch_ips:
            data = {
                "type": "A",
                "name": record_name,
                "content": ip,
                "ttl": 1,
                "proxied": False
            }

            try:
                response = requests.post(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', json=data, headers=headers, timeout=TIMEOUT)
                print(f"Attempting to add A record for {record_name} with IP {ip}: {response.status_code} {response.text}")  # 调试输出
                if response.status_code == 200:
                    print(f"Add {subdomain}:{ip}")
                else:
                    print(f"Failed to add A record for IP {ip} to subdomain {subdomain}: {response.status_code} {response.text}")

            except RequestException as e:
                print(f"Error updating DNS record for {record_name} with IP {ip}: {e}")

        # 每处理完一批 IP，等待几秒钟再进行下一批更新，避免请求过于频繁
        time.sleep(5)

if __name__ == "__main__":
    api_token = os.getenv('CF_API_TOKEN')

    # 示例URL和子域名对应的IP列表
    subdomain_ip_mapping = {
        '443ip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/443ip.txt',
        '80ip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/80ip.txt',
        'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/ip.txt', #域名二，api.域名.com
        'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/nodie.txt',
        'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/cfip.txt',
        'bestcf': 'https://ipdb.030101.xyz/api/bestcf.txt',  # #域名一，bestcf.域名.com
        'xiaoqi222': 'https://addressesapi.090227.xyz/CloudFlareYes',  # 非txt文件
        'xiaoqi333': 'https://ip.164746.xyz/ipTop10.html',  # 非txt文件
        # 添加更多子域名和对应的IP列表URL
    }

    try:
        # 获取Cloudflare域区ID和域名
        zone_id, domain = get_cloudflare_zone(api_token)

        if zone_id is None or domain is None:
            raise Exception("Cloudflare Zone retrieval failed")

        for subdomain, url in subdomain_ip_mapping.items():
            # 获取IP列表
            ip_list = get_ip_list(url)
            if not ip_list:
                print(f"No IPs found for {subdomain}. Skipping DNS update.")
                continue

            # 删除现有的DNS记录
            delete_existing_dns_records(api_token, zone_id, subdomain, domain)

            # 更新Cloudflare DNS记录
            update_cloudflare_dns(ip_list, api_token, zone_id, subdomain, domain)

    except Exception as e:
        # 处理异常并输出错误信息
        print(f"An error occurred: {e}")
