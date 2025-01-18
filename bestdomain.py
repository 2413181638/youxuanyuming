import os
import re
import time
import requests
import threading
from lxml import etree
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# 设置全局超时
TIMEOUT = 10  # 设置请求超时时间为10秒
MAX_TIMEOUT = 180  # 最大超时时间，3分钟
MAX_RETRIES = 3  # 最大重试次数
MAX_THREADS = 20  # 最大并发线程数

def request_with_retry(method, url, headers=None, json=None, params=None, data=None, timeout=TIMEOUT, max_retries=MAX_RETRIES, initial_delay=2):
    """
    封装requests的调用，增加重试和延时逻辑，避免被API限频。
    :param method: 请求方法，如 'GET', 'POST', 'DELETE' 等
    :param url: 请求URL
    :param headers: 请求头
    :param json: JSON数据体（可选）
    :param params: URL参数（可选）
    :param data: 表单数据（可选）
    :param timeout: 超时时间（秒）
    :param max_retries: 最大重试次数
    :param initial_delay: 初始等待时长，后续可指数退避
    :return: requests.Response 或抛出异常
    """
    delay = initial_delay
    for attempt in range(1, max_retries + 1):
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=json, data=data, timeout=timeout)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            # 如果触发 Cloudflare 429，休眠后重试
            if response.status_code == 429:
                print(f"[{attempt}/{max_retries}] HTTP 429 Too Many Requests. Sleeping {delay} seconds before retry...")
                time.sleep(delay)
                # 指数退避
                delay *= 2
                continue

            # 其他非200状态码，也需检查
            response.raise_for_status()
            return response

        except RequestException as e:
            # 可以根据需要，对不同的错误进行区分处理
            print(f"[{attempt}/{max_retries}] Request failed: {e}. Sleeping {delay} seconds before retry...")
            time.sleep(delay)
            delay *= 2

    # 超过最大重试次数，依旧失败
    raise Exception(f"Request to {url} failed after {max_retries} retries.")

def get_ip_list(url):
    if url.endswith('.txt'):
        try:
            response = request_with_retry(
                method='GET',
                url=url,
                timeout=TIMEOUT,
                max_retries=3,         # 可自定义
                initial_delay=2        # 可自定义
            )
            ip_list = response.text.strip().split('\n')
            return ip_list
        except Exception as e:
            print(f"Error fetching IP list from {url}: {e}")
            return []
    else:
        return parse_html_for_ips(url)

def parse_html_for_ips(url):
    try:
        response = request_with_retry(
            method='GET',
            url=url,
            timeout=TIMEOUT,
            max_retries=3,
            initial_delay=2
        )
        soup = BeautifulSoup(response.text, 'html.parser')
        ip_list = []

        for item in soup.find_all('a', href=True):
            ip = item.get_text().strip()
            if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip):
                ip_list.append(ip)

        if ip_list:
            return ip_list
        else:
            return []
    except Exception as e:
        print(f"Error fetching or parsing HTML from {url}: {e}")
        return []

def update_cloudflare_dns_threaded(ip_list, api_token, zone_id, subdomain, domain):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    record_name = domain if subdomain == '@' else f'{subdomain}.{domain}'

    def add_dns_record(ip):
        data = {
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": 1,
            "proxied": False
        }
        try:
            response = request_with_retry(
                method='POST',
                url=f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records',
                headers=headers,
                json=data,
                timeout=TIMEOUT,
                max_retries=3,
                initial_delay=2
            )
            if response.status_code == 200:
                print(f"Added A record for {record_name} with IP {ip}")
            else:
                print(f"Failed to add A record for IP {ip}: {response.status_code} {response.text}")

        except Exception as e:
            print(f"Error adding A record for {record_name} with IP {ip}: {e}")

    threads = []
    for ip in ip_list:
        thread = threading.Thread(target=add_dns_record, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # 等待所有线程完成

def get_cloudflare_zone(api_token):
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }
    try:
        response = request_with_retry(
            method='GET',
            url='https://api.cloudflare.com/client/v4/zones',
            headers=headers,
            timeout=TIMEOUT,
            max_retries=3,
            initial_delay=2
        )
        zones = response.json().get('result', [])
        if not zones:
            raise Exception("No zones found")
        return zones[0]['id'], zones[0]['name']
    except Exception as e:
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
            response = request_with_retry(
                method='GET',
                url=f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={record_name}',
                headers=headers,
                timeout=TIMEOUT,
                max_retries=3,
                initial_delay=2
            )
            records = response.json().get('result', [])

            if not records:
                break

            for record in records:
                delete_response = request_with_retry(
                    method='DELETE',
                    url=f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record["id"]}',
                    headers=headers,
                    timeout=TIMEOUT,
                    max_retries=3,
                    initial_delay=2
                )

        except Exception as e:
            print(f"Error deleting DNS records for {record_name}: {e}")
            break

if __name__ == "__main__":
    api_token = os.getenv('CF_API_TOKEN')

    subdomain_ip_mapping = {
        '443ip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/443ip.txt',
        'xiaoqi': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/ip.txt',
        'nodie': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/nodie.txt',
        'cfip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/cfip.txt',
        'bestcf': 'https://ipdb.030101.xyz/api/bestcf.txt',
        'xiaoqi222': 'https://addressesapi.090227.xyz/CloudFlareYes',
        'xiaoqi333': 'https://ip.164746.xyz/ipTop10.html',
        '80ip': 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/80ip.txt',
    }

    try:
        zone_id, domain = get_cloudflare_zone(api_token)
        if not zone_id or not domain:
            raise Exception("Cloudflare Zone retrieval failed")

        for subdomain, url in subdomain_ip_mapping.items():
            ip_list = get_ip_list(url)  # Make sure this line is indented
            if ip_list:
                print(f"Updating DNS records for {subdomain}.{domain}...")
                delete_existing_dns_records(api_token, zone_id, subdomain, domain)
                update_cloudflare_dns_threaded(ip_list, api_token, zone_id, subdomain, domain)
            else:
                print(f"No IPs found for {subdomain}.{domain} from {url}")
    except Exception as e:
        print(f"Error: {e}")
