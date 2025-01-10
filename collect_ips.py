import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress  # 用于验证IP地址有效性
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import random
import logging
import subprocess
import sys

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# 目标URL列表
urls = [
    'https://cf.090227.xyz',
    'https://ip.164746.xyz/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
    'https://vps789.com/public/sum/cfIpApi',
    'https://github.com/ymyuuu/IPDB/blob/main/bestcf.txt',
    'https://raw.githubusercontent.com/jc-lw/youxuanyuming/refs/heads/main/ip.txt',
    'https://ipdb.030101.xyz/api/bestcf.txt',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://cf.vvhan.com/'
]

# 正则表达式用于匹配IP地址，包括类似 "172.67.195.213#CM-Default" 的结构
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# 检查ip.txt文件是否存在, 如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 创建一个集合来存储去重后的IP地址
unique_ips = set()

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
    """设置请求会话，包含超时和重试机制，增强处理429错误"""
    session = requests.Session()
    retries = Retry(
        total=5,  # 增加重试次数
        backoff_factor=1,  # 增加退避因子
        status_forcelist=[429, 500, 502, 503, 504],  # 包含429错误
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]  # 允许重试的方法
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_ips(url, session):
    """从指定URL提取IP地址，每个URL最多提取前20个IP地址"""
    ip_matches = []
    try:
        logging.info(f"正在请求 {url} ...")
        response = session.get(url, timeout=20)  # 设置超时为20秒
        response.raise_for_status()  # 检查请求是否成功

        # 检查内容类型
        content_type = response.headers.get('Content-Type', '')

        # 如果是纯文本
        if 'text/plain' in content_type or 'text' in content_type:
            logging.info(f"{url} 返回纯文本，直接使用正则提取")
            ip_matches = re.findall(ip_pattern, response.text)

        # 如果是HTML内容
        elif 'html' in content_type:
            logging.info(f"{url} 返回HTML，尝试解析")
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
                logging.warning(f"无法自动解析 {url}, 需要手动检查结构")

            # 遍历找到的元素，提取IP地址
            for element in elements:
                element_text = element.get_text()
                ip_matches.extend(re.findall(ip_pattern, element_text))

        # 尝试从JSON结构中提取IP地址
        if response.headers.get('Content-Type', '').startswith('application/json'):
            logging.info(f"{url} 返回JSON，尝试解析")
            try:
                json_ips = re.findall(ip_pattern, response.text)
                ip_matches.extend(json_ips)
            except Exception as json_error:
                logging.error(f"解析JSON时出错: {json_error}")

        # 将有效的IP添加到集合中，集合会自动去重
        valid_ips = 0
        for ip in ip_matches[:20]:  # 限制每个URL最多提取20个IP
            if is_valid_ip(ip):
                unique_ips.add(ip)
                valid_ips += 1

        logging.info(f"{url} 提取到 {valid_ips} 个有效 IP")

    except requests.exceptions.RequestException as e:
        logging.error(f"请求 {url} 时出错: {e}")
    except Exception as e:
        logging.error(f"解析 {url} 时出错: {e}")

def git_pull():
    """
    执行 git pull 操作，以确保本地仓库与远程仓库同步。
    使用 --rebase 选项以避免产生额外的合并提交。
    """
    try:
        logging.info("正在执行 git pull --rebase...")
        result = subprocess.run(['git', 'pull', '--rebase'], check=True, capture_output=True, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"git pull 失败: {e.stderr}")
        raise

def git_push():
    """
    执行 git push 操作。
    """
    try:
        logging.info("正在执行 git push...")
        result = subprocess.run(['git', 'push'], check=True, capture_output=True, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"git push 失败: {e.stderr}")
        raise

def git_commit_push():
    """
    执行 git commit 和 git push 操作。
    """
    try:
        # 添加文件到暂存区
        subprocess.run(['git', 'add', 'ip.txt'], check=True, capture_output=True, text=True)
        logging.info("已添加 ip.txt 到暂存区。")

        # 提交更改
        commit_message = 'Automatic update'
        subprocess.run(['git', 'commit', '-m', commit_message], check=True, capture_output=True, text=True)
        logging.info(f"已提交更改: {commit_message}")

        # 推送更改
        git_push()

    except subprocess.CalledProcessError as e:
        # 如果没有更改需要提交，git commit 会失败，此时忽略
        if 'nothing to commit' in e.stderr.lower():
            logging.info("没有检测到更改，跳过提交和推送。")
        else:
            logging.error(f"git commit 或 push 失败: {e.stderr}")
            raise

def configure_git():
    """
    配置 Git 用户信息。
    """
    try:
        git_user_email = os.getenv('GIT_USER_EMAIL')
        git_user_name = os.getenv('GIT_USER_NAME')

        if not git_user_email or not git_user_name:
            logging.error("环境变量 GIT_USER_EMAIL 和 GIT_USER_NAME 未设置。")
            sys.exit(1)

        subprocess.run(['git', 'config', '--global', 'user.email', git_user_email], check=True, capture_output=True, text=True)
        subprocess.run(['git', 'config', '--global', 'user.name', git_user_name], check=True, capture_output=True, text=True)
        logging.info("已配置 Git 用户信息。")
    except subprocess.CalledProcessError as e:
        logging.error(f"配置 Git 用户信息失败: {e.stderr}")
        raise

def configure_git_remote():
    """
    配置 Git 远程仓库 URL，包含认证信息。
    使用环境变量 GIT_AUTH_TOKEN 来进行认证。
    """
    try:
        git_auth_token = os.getenv('GIT_AUTH_TOKEN')
        git_repo_url = os.getenv('GIT_REPO_URL')  # 完整的远程仓库URL，例如 https://github.com/username/repo.git

        if not git_auth_token or not git_repo_url:
            logging.error("环境变量 GIT_AUTH_TOKEN 和 GIT_REPO_URL 未设置。")
            sys.exit(1)

        # 构建带有令牌的远程URL
        # 例如：https://<token>@github.com/username/repo.git
        parsed_url = re.match(r'https://github\.com/(.+)', git_repo_url)
        if not parsed_url:
            logging.error("GIT_REPO_URL 格式不正确。应为 https://github.com/username/repo.git")
            sys.exit(1)
        
        authenticated_url = f'https://{git_auth_token}@github.com/{parsed_url.group(1)}'

        # 设置远程仓库URL
        subprocess.run(['git', 'remote', 'set-url', 'origin', authenticated_url], check=True, capture_output=True, text=True)
        logging.info("已配置带有认证信息的远程仓库URL。")
    except subprocess.CalledProcessError as e:
        logging.error(f"配置远程仓库URL失败: {e.stderr}")
        raise

def main():
    # 配置 Git 用户信息
    configure_git()

    # 配置 Git 远程仓库URL（带认证）
    configure_git_remote()

    # 设置会话，包含超时和重试机制
    session = setup_session()

    # 使用多线程并发请求，降低并发数
    max_workers = 3  # 从5降到3，进一步降低并发请求数量
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(fetch_ips, url, session): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
                # 每完成一个请求后，随机等待0.5到2秒
                sleep_time = random.uniform(0.5, 2.0)
                logging.info(f"完成 {url}，等待 {sleep_time:.2f} 秒")
                time.sleep(sleep_time)
            except Exception as exc:
                logging.error(f"{url} 生成异常: {exc}")

    # 将去重后的IP写入文件
    with open('ip.txt', 'w') as file:
        for ip in sorted(unique_ips, key=lambda x: tuple(map(int, x.split('.')))):
            file.write(ip + '\n')

    logging.info(f'所有IP地址已去重并保存到ip.txt文件中，去重后的IP数量：{len(unique_ips)}')

    try:
        # 执行 Git 操作
        git_pull()   # 首先拉取远程更改
        git_commit_push()   # 添加、提交并推送更改
    except Exception as e:
        logging.error(f"Git 操作失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
