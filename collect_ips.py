import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import random
import logging
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# 修正后的目标URL列表（处理GitHub raw内容）
urls = [
    'https://cf.090227.xyz',
    'https://ip.164746.xyz/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
    'https://vps789.com/public/sum/cfIpApi',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/main/bestcf.txt',  # 修正GitHub raw地址
    'https://raw.githubusercontent.com/jc-lw/youxuanyuming/main/ip.txt',
    'https://ipdb.030101.xyz/api/bestcf.txt',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://stock.hostmonit.com/CloudFlareYes',  # 需要特殊处理
    'https://cf.vvhan.com/'
]

# 更严格的IP正则表达式（排除非法数字）
STRICT_IP_PATTERN = r'\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.' \
                    r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.' \
                    r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.' \
                    r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'

# 排除更多保留地址
RESERVED_RANGES = [
    ipaddress.IPv4Network('0.0.0.0/8'),
    ipaddress.IPv4Network('100.64.0.0/10'),
    ipaddress.IPv4Network('169.254.0.0/16'),
    ipaddress.IPv4Network('192.0.0.0/24'),
    ipaddress.IPv4Network('192.0.2.0/24'),
    ipaddress.IPv4Network('224.0.0.0/4'),
    ipaddress.IPv4Network('240.0.0.0/4'),
]

private_ip_ranges = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8')
] + RESERVED_RANGES

def is_valid_ip(ip):
    """严格验证IPv4地址有效性"""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_global and not any(ip_obj in network for network in private_ip_ranges):
            return True
        return False
    except ipaddress.AddressValueError:
        return False

def setup_session():
    """配置带有自定义Header和智能重试的会话"""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8'
    })
    return session

def handle_special_url(url, session):
    """处理需要特殊请求方式的URL"""
    if url == 'https://stock.hostmonit.com/CloudFlareYes':
        try:
            response = session.post(
                url,
                json={"key": "iampassword"},  # 这个API需要特定参数
                timeout=15
            )
            response.raise_for_status()
            return [item.get("ip") for item in response.json() if isinstance(item, dict)]
        except Exception as e:
            logging.error(f"特殊处理 {url} 失败: {e}")
            return []
    return None

def extract_ips_from_html(text):
    """从HTML内容中提取IP"""
    soup = BeautifulSoup(text, 'html.parser')
    candidates = []
    
    # 尝试常见标签
    for tag in ['tr', 'td', 'li', 'div', 'code', 'pre']:
        elements = soup.find_all(tag)
        for el in elements:
            candidates.extend(re.findall(STRICT_IP_PATTERN, el.get_text()))
        if candidates:
            break
    
    return list(set(candidates))  # 初步去重

def extract_ips_from_json(text):
    """从JSON内容中深度提取IP"""
    try:
        data = json.loads(text)
        ips = []
        
        def json_iter(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and re.match(STRICT_IP_PATTERN, v):
                        ips.append(v)
                    else:
                        json_iter(v)
            elif isinstance(obj, list):
                for item in obj:
                    json_iter(item)
        
        json_iter(data)
        return ips
    except json.JSONDecodeError:
        return []

def fetch_ips(url, session):
    """智能获取并解析IP地址"""
    try:
        logging.info(f"🔍 开始处理 {url}")
        start_time = time.time()
        
        # 特殊URL处理
        special_result = handle_special_url(url, session)
        if special_result is not None:
            return special_result

        response = session.request(
            'GET' if url != 'https://stock.hostmonit.com/CloudFlareYes' else 'POST',
            url,
            timeout=15
        )
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()
        ips = []

        # 根据内容类型选择解析方式
        if 'json' in content_type:
            ips = extract_ips_from_json(response.text)
            logging.debug(f"{url} JSON解析找到 {len(ips)} 个候选IP")
        elif 'html' in content_type:
            ips = extract_ips_from_html(response.text)
            logging.debug(f"{url} HTML解析找到 {len(ips)} 个候选IP")
        else:  # 纯文本处理
            ips = re.findall(STRICT_IP_PATTERN, response.text)
            logging.debug(f"{url} 纯文本找到 {len(ips)} 个候选IP")

        # 验证并限制数量
        valid_ips = [ip for ip in ips if is_valid_ip(ip)][:30]  # 每个源最多取30个
        
        logging.info(f"✅ {url} 耗时 {(time.time()-start_time):.2f}s | 有效IP {len(valid_ips)}/{len(ips)}")
        return valid_ips

    except Exception as e:
        logging.warning(f"❌ {url} 处理失败: {str(e)}")
        return []

def main():
    unique_ips = set()
    session = setup_session()
    
    # 删除旧文件
    if os.path.exists('ip.txt'):
        os.remove('ip.txt')

    # 动态并发控制（根据响应时间调整）
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_ips, url, session): url for url in urls}
        
        for future in as_completed(futures):
            try:
                results = future.result()
                for ip in results:
                    unique_ips.add(ip)
                # 动态间隔（根据服务器响应时间调整）
                time.sleep(random.uniform(0.2, 1.5))
            except Exception as e:
                logging.error(f"线程异常: {str(e)}")

    # 写入文件并排序
    with open('ip.txt', 'w') as f:
        sorted_ips = sorted(unique_ips, key=lambda x: tuple(map(int, x.split('.'))))
        f.write('\n'.join(sorted_ips))
    
    logging.info(f"🎉 完成！共收集到 {len(sorted_ips)} 个有效IP")

if __name__ == "__main__":
    main()
