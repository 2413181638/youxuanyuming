import requests
from bs4 import BeautifulSoup
import re
import os

# 目标URL列表
urls = [
    'https://ip.164746.xyz/ipTop10.html',
    'https://cf.090227.xyz',
    'https://vps789.com/public/sum/cfIpApi',
    'https://www.wetest.vip/page/cloudflare/address_v4.html',
    'https://api.uouin.com/cloudflare.html',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://cf.vvhan.com/'
]

# 正则表达式用于匹配IP地址
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# 检查ip.txt文件是否存在, 如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 创建一个文件来存储IP地址
with open('ip.txt', 'w') as file:
    for url in urls:
        try:
            # 发送HTTP请求获取网页内容
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # 使用BeautifulSoup解析HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # 动态判断标签
            if soup.find_all('tr'):
                elements = soup.find_all('tr')  # 表格行
            elif soup.find_all('li'):
                elements = soup.find_all('li')  # 列表项
            elif soup.find_all('div'):
                elements = soup.find_all('div')  # 区块
            else:
                print(f"无法自动解析 {url}, 需要手动检查结构")
                continue

            # 遍历找到的元素，提取IP地址
            for element in elements:
                element_text = element.get_text()
                ip_matches = re.findall(ip_pattern, element_text)
                
                # 如果找到IP地址, 写入文件
                for ip in ip_matches:
                    file.write(ip + '\n')

        except Exception as e:
            print(f"解析 {url} 时出错: {e}")

print('IP地址已保存到ip.txt文件中。')
