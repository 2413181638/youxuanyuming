import requests
import re
from bs4 import BeautifulSoup
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 目标URL列表（存入ip.txt）
urls = [
    'https://cf.090227.xyz',
    'https://ip.164746.xyz/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
    'https://vps789.com/public/sum/cfIpApi',
    'https://github.com/ymyuuu/IPDB/blob/main/bestcf.txt',
    'https://ipdb.030101.xyz/api/bestcf.txt',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://cf.vvhan.com/'
]

# 指定链接（存入ips.txt）
ips_file_url = 'https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/ips.txt'

# 正则表达式用于匹配IP地址
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# 创建一个集合来存储去重后的IP地址
ip_set = set()  # 存储ip.txt的IP
ips_set = set()  # 存储ips.txt的IP

# 私有IP地址段
private_ip_ranges = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8')
]

def is_valid_ip(ip):
    """检查IP地址是否有效，并且不是私有IP地址"""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        # 判断是否为私有IP
        for private_range in private_ip_ranges:
            if ip_obj in private_range:
                return False
        return True
    except ipaddress.AddressValueError:
        return False  # 如果IP格式不正确，返回False

def setup_session():
    """设置请求会话，包含超时和重试机制"""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_ips(url, session, target_set):
    """从指定URL提取IP地址"""
    ip_matches = []
    try:
        print(f"正在请求 {url} ...")
        response = session.get(url, timeout=20)  # 设置超时为20秒
        response.raise_for_status()  # 检查请求是否成功

        # 检查内容类型
        content_type = response.headers.get('Content-Type', '')

        # 如果是纯文本
        if 'text/plain' in content_type or 'text' in content_type:
            print(f"{url} 返回纯文本，直接使用正则提取")
            ip_matches = re.findall(ip_pattern, response.text)

        # 如果是HTML内容
        elif 'html' in content_type:
            print(f"{url} 返回HTML，尝试解析")
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = []

            # 动态判断标签
            if soup.find_all('tr'):
                elements = soup.find_all('tr')  # 表格行
            elif soup.find_all('li'):
                elements = soup.find_all('li')  # 列表项
            elif soup.find_all('div'):
                elements = soup.find_all('div')  # 区块
            else:
                print(f"无法自动解析 {url}, 需要手动检查结构")

            # 遍历找到的元素，提取IP地址
            for element in elements:
                element_text = element.get_text()
                ip_matches.extend(re.findall(ip_pattern, element_text))

        # 尝试从JSON结构中提取IP地址
        if response.headers.get('Content-Type', '').startswith('application/json'):
            print(f"{url} 返回JSON，尝试解析")
            try:
                json_ips = re.findall(ip_pattern, response.text)
                ip_matches.extend(json_ips)
            except Exception as json_error:
                print(f"解析JSON时出错: {json_error}")

        # 将有效的IP添加到指定的集合中，集合会自动去重
        for ip in ip_matches:
            if is_valid_ip(ip):
                target_set.add(ip)

        print(f"{url} 提取到 {len(ip_matches)} 个 IP")

    except requests.exceptions.RequestException as e:
        print(f"请求 {url} 时出错: {e}")
    except Exception as e:
        print(f"解析 {url} 时出错: {e}")

def main():
    # 设置会话，包含超时和重试机制
    session = setup_session()

    # 使用多线程并发请求
    with ThreadPoolExecutor(max_workers=5) as executor:
        # 从指定的URL存储到ips.txt
        executor.map(lambda url: fetch_ips(url, session, ips_set), [ips_file_url])
        # 从其他URL存储到ip.txt
        executor.map(lambda url: fetch_ips(url, session, ip_set), urls)

    # 将所有的IP地址存入ip.txt文件
    with open('ip.txt', 'w') as ip_file:
        for ip in ip_set:
            ip_file.write(ip + '\n')

    # 将所有的IP地址存入ips.txt文件
    with open('ips.txt', 'w') as ips_file:
        for ip in ips_set:
            ips_file.write(ip + '\n')

    print(f'所有IP地址已去重并保存到ip.txt文件中，去重后的IP数量：{len(ip_set)}')
    print(f'所有IP地址已去重并保存到ips.txt文件中，去重后的IP数量：{len(ips_set)}')

if __name__ == "__main__":
    main()
