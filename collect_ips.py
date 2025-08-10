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

# ===== 日志配置（想更安静可改成 WARNING）=====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

# ===== 目标 URL 列表 =====
URLS = [
    'https://cf.090227.xyz',
    'https://ip.164746.xyz/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/main/bestcf.txt',
    'https://vps789.com/public/sum/cfIpApi',
    'https://raw.githubusercontent.com/jc-lw/youxuanyuming/main/ip.txt',
    'https://ipdb.030101.xyz/api/bestcf.txt',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://cf.vvhan.com/'
]

# ===== 非捕获组 IPv4 正则（返回完整字符串）=====
IP_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)

# ===== 保留/私网段 =====
RESERVED_RANGES = [
    ipaddress.IPv4Network('0.0.0.0/8'),
    ipaddress.IPv4Network('100.64.0.0/10'),
    ipaddress.IPv4Network('169.254.0.0/16'),
    ipaddress.IPv4Network('192.0.0.0/24'),
    ipaddress.IPv4Network('192.0.2.0/24'),
    ipaddress.IPv4Network('224.0.0.0/4'),
    ipaddress.IPv4Network('240.0.0.0/4'),
]
PRIVATE_RANGES = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8')
] + RESERVED_RANGES

def is_valid_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_global and not any(ip_obj in net for net in PRIVATE_RANGES)
    except ipaddress.AddressValueError:
        return False

def normalize_candidate(s: str) -> str:
    # 去端口/掩码等
    s = s.strip()
    s = s.split('/', 1)[0]
    s = s.split(':', 1)[0]
    return s

def find_ips_in_text(text: str) -> list[str]:
    return [m.group(0) for m in IP_RE.finditer(text)]

def setup_session() -> requests.Session:
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

def handle_special_url(url: str, session: requests.Session):
    # hostmonit 可能需要有效 key；无则返回空
    if url == 'https://stock.hostmonit.com/CloudFlareYes':
        try:
            resp = session.post(url, json={"key": "iampassword"}, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            ips = []
            for item in data if isinstance(data, list) else []:
                ip = item.get("ip")
                if isinstance(ip, str):
                    ip = normalize_candidate(ip)
                    if IP_RE.fullmatch(ip):
                        ips.append(ip)
            return ips
        except Exception as e:
            logging.warning(f"特殊源失败 {url}: {e}")
            return []
    return None

def extract_ips_from_json_text(text: str) -> list[str]:
    ips = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ips

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for it in obj:
                walk(it)
        elif isinstance(obj, str):
            cand = normalize_candidate(obj)
            if IP_RE.fullmatch(cand):
                ips.append(cand)

    walk(data)
    return ips

def fetch_ips(url: str, session: requests.Session) -> list[str]:
    try:
        logging.info(f"🔍 处理 {url}")
        start = time.time()

        # 特殊处理
        sp = handle_special_url(url, session)
        if sp is not None:
            logging.info(f"✅ {url} 耗时 {time.time()-start:.2f}s | 得到 {len(sp)} 个候选")
            return sp

        method = 'GET'
        resp = session.request(method, url, timeout=15, verify=True)
        resp.raise_for_status()

        ctype = resp.headers.get('Content-Type', '').lower()
        if 'json' in ctype:
            ips = extract_ips_from_json_text(resp.text)
        else:
            # HTML / 纯文本统一用文本正则；HTML 无需解析标签也能抓干净
            ips = find_ips_in_text(resp.text)

        # 规范化 + 只保留有效公网 IP，且每源至多取 30 个
        clean = []
        for ip in ips:
            ip = normalize_candidate(ip)
            if is_valid_ip(ip):
                clean.append(ip)
            if len(clean) >= 30:
                break

        logging.info(f"✅ {url} 耗时 {time.time()-start:.2f}s | 有效IP {len(clean)}/{len(ips)}")
        return clean

    except requests.exceptions.SSLError as e:
        logging.warning(f"❌ SSL 错误 {url}: {e}")
        return []
    except Exception as e:
        logging.warning(f"❌ 失败 {url}: {e}")
        return []

def main():
    session = setup_session()
    unique_ips = set()

    # 删除旧文件
    if os.path.exists('ip.txt'):
        os.remove('ip.txt')

    # 并发抓取
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fetch_ips, u, session): u for u in URLS}
        for fut in as_completed(futures):
            try:
                for ip in fut.result():
                    if is_valid_ip(ip):
                        unique_ips.add(ip)
                time.sleep(random.uniform(0.2, 1.0))  # 礼貌延时
            except Exception as e:
                logging.error(f"线程异常: {e}")

    # 排序写入（纯 IP 列表）
    sorted_ips = sorted(unique_ips, key=lambda s: tuple(map(int, s.split('.'))))
    with open('ip.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_ips))

    logging.info(f"🎉 完成！共写入 {len(sorted_ips)} 个 IP 到 ip.txt")

if __name__ == "__main__":
    main()
