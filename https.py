import requests
import re
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# 关闭 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置
TIMEOUT = 10
MAX_THREADS = 2
FAST_THRESHOLD = 2.0
TEST_URL = "https://www.apple.com/library/test/success.html"
MAX_RETRIES = 2

# 国家代码 -> 中文名映射（部分常用）
COUNTRY_MAP = {
    "AF": "阿富汗", "AX": "奥兰群岛", "AL": "阿尔巴尼亚", "DZ": "阿尔及利亚", "AS": "美属萨摩亚", "AD": "安道尔",
    "AO": "安哥拉", "AI": "安圭拉", "AQ": "南极洲", "AG": "安提瓜和巴布达", "AR": "阿根廷", "AM": "亚美尼亚",
    "AW": "阿鲁巴", "AU": "澳大利亚", "AT": "奥地利", "AZ": "阿塞拜疆", "BS": "巴哈马", "BH": "巴林",
    "BD": "孟加拉国", "BB": "巴巴多斯", "BY": "白俄罗斯", "BE": "比利时", "BZ": "伯利兹", "BJ": "贝宁",
    "BM": "百慕大", "BT": "不丹", "BO": "玻利维亚", "BQ": "荷兰加勒比区", "BA": "波斯尼亚和黑塞哥维那",
    "BW": "博茨瓦纳", "BV": "布韦岛", "BR": "巴西", "IO": "英属印度洋领地", "BN": "文莱", "BG": "保加利亚",
    "BF": "布基纳法索", "BI": "布隆迪", "KH": "柬埔寨", "CM": "喀麦隆", "CA": "加拿大", "CV": "佛得角",
    "KY": "开曼群岛", "CF": "中非共和国", "TD": "乍得", "CL": "智利", "CN": "中国", "CX": "圣诞岛",
    "CC": "科科斯（基林）群岛", "CO": "哥伦比亚", "KM": "科摩罗", "CG": "刚果（布）", "CD": "刚果（金）",
    "CK": "库克群岛", "CR": "哥斯达黎加", "CI": "科特迪瓦", "HR": "克罗地亚", "CU": "古巴", "CW": "库拉索",
    "CY": "塞浦路斯", "CZ": "捷克", "DK": "丹麦", "DJ": "吉布提", "DM": "多米尼克", "DO": "多米尼加共和国",
    "EC": "厄瓜多尔", "EG": "埃及", "SV": "萨尔瓦多", "GQ": "赤道几内亚", "ER": "厄立特里亚", "EE": "爱沙尼亚",
    "ET": "埃塞俄比亚", "FK": "福克兰群岛", "FO": "法罗群岛", "FJ": "斐济", "FI": "芬兰", "FR": "法国",
    "GF": "法属圭亚那", "PF": "法属波利尼西亚", "TF": "法属南部领地", "GA": "加蓬", "GM": "冈比亚",
    "GE": "格鲁吉亚", "DE": "德国", "GH": "加纳", "GI": "直布罗陀", "GR": "希腊", "GL": "格陵兰",
    "GD": "格林纳达", "GP": "瓜德罗普", "GU": "关岛", "GT": "危地马拉", "GG": "根西岛", "GN": "几内亚",
    "GW": "几内亚比绍", "GY": "圭亚那", "HT": "海地", "HM": "赫德岛和麦克唐纳群岛", "VA": "梵蒂冈",
    "HN": "洪都拉斯", "HK": "中国香港", "HU": "匈牙利", "IS": "冰岛", "IN": "印度", "ID": "印度尼西亚",
    "IR": "伊朗", "IQ": "伊拉克", "IE": "爱尔兰", "IM": "马恩岛", "IL": "以色列", "IT": "意大利",
    "JM": "牙买加", "JP": "日本", "JE": "泽西岛", "JO": "约旦", "KZ": "哈萨克斯坦", "KE": "肯尼亚",
    "KI": "基里巴斯", "KP": "朝鲜", "KR": "韩国", "KW": "科威特", "KG": "吉尔吉斯斯坦", "LA": "老挝",
    "LV": "拉脱维亚", "LB": "黎巴嫩", "LS": "莱索托", "LR": "利比里亚", "LY": "利比亚", "LI": "列支敦士登",
    "LT": "立陶宛", "LU": "卢森堡", "MO": "中国澳门", "MK": "北马其顿", "MG": "马达加斯加", "MW": "马拉维",
    "MY": "马来西亚", "MV": "马尔代夫", "ML": "马里", "MT": "马耳他", "MH": "马绍尔群岛", "MQ": "马提尼克",
    "MR": "毛里塔尼亚", "MU": "毛里求斯", "YT": "马约特", "MX": "墨西哥", "FM": "密克罗尼西亚", "MD": "摩尔多瓦",
    "MC": "摩纳哥", "MN": "蒙古", "ME": "黑山", "MS": "蒙特塞拉特", "MA": "摩洛哥", "MZ": "莫桑比克",
    "MM": "缅甸", "NA": "纳米比亚", "NR": "瑙鲁", "NP": "尼泊尔", "NL": "荷兰", "NC": "新喀里多尼亚",
    "NZ": "新西兰", "NI": "尼加拉瓜", "NE": "尼日尔", "NG": "尼日利亚", "NU": "纽埃", "NF": "诺福克岛",
    "MP": "北马里亚纳群岛", "NO": "挪威", "OM": "阿曼", "PK": "巴基斯坦", "PW": "帕劳", "PS": "巴勒斯坦",
    "PA": "巴拿马", "PG": "巴布亚新几内亚", "PY": "巴拉圭", "PE": "秘鲁", "PH": "菲律宾", "PN": "皮特凯恩群岛",
    "PL": "波兰", "PT": "葡萄牙", "PR": "波多黎各", "QA": "卡塔尔", "RE": "留尼汪", "RO": "罗马尼亚",
    "RU": "俄罗斯", "RW": "卢旺达", "BL": "圣巴泰勒米", "SH": "圣赫勒拿", "KN": "圣基茨和尼维斯",
    "LC": "圣卢西亚", "MF": "法属圣马丁", "PM": "圣皮埃尔和密克隆", "VC": "圣文森特和格林纳丁斯",
    "WS": "萨摩亚", "SM": "圣马力诺", "ST": "圣多美和普林西比", "SA": "沙特阿拉伯", "SN": "塞内加尔",
    "RS": "塞尔维亚", "SC": "塞舌尔", "SL": "塞拉利昂", "SG": "新加坡", "SX": "荷属圣马丁",
    "SK": "斯洛伐克", "SI": "斯洛文尼亚", "SB": "所罗门群岛", "SO": "索马里", "ZA": "南非", "GS": "南乔治亚和南桑威奇群岛",
    "SS": "南苏丹", "ES": "西班牙", "LK": "斯里兰卡", "SD": "苏丹", "SR": "苏里南", "SJ": "斯瓦尔巴和扬马延",
    "SZ": "斯威士兰", "SE": "瑞典", "CH": "瑞士", "SY": "叙利亚", "TW": "中国台湾", "TJ": "塔吉克斯坦",
    "TZ": "坦桑尼亚", "TH": "泰国", "TL": "东帝汶", "TG": "多哥", "TK": "托克劳", "TO": "汤加",
    "TT": "特立尼达和多巴哥", "TN": "突尼斯", "TR": "土耳其", "TM": "土库曼斯坦", "TC": "特克斯和凯科斯群岛",
    "TV": "图瓦卢", "UG": "乌干达", "UA": "乌克兰", "AE": "阿联酋", "GB": "英国", "US": "美国", "UM": "美国本土外小岛屿",
    "UY": "乌拉圭", "UZ": "乌兹别克斯坦", "VU": "瓦努阿图", "VE": "委内瑞拉", "VN": "越南", "VG": "英属维尔京群岛",
    "VI": "美属维尔京群岛", "WF": "瓦利斯和富图纳", "EH": "西撒哈拉", "YE": "也门", "ZM": "赞比亚",
    "ZW": "津巴布韦"
}


def country_to_cn(code):
    return COUNTRY_MAP.get(code.upper(), code)

def extract_ip_port_proto(line):
    match = re.match(r"(\d+\.\d+\.\d+\.\d+:\d+)(?::(https?|socks5))?", line.lower())
    if match:
        ip_port = match.group(1)
        proto = match.group(2) if match.group(2) else "http"
        return ip_port, proto
    return None, None

def check_ip_info(ip):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://pingip.cn/",
        "Accept": "application/json, text/plain, */*"
    }
    for attempt in range(3):
        try:
            url = f"https://pingip.cn/api/lookup/{ip}"
            # 注意：这里需要加入 headers
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                ip_type = data.get("ipType", {}).get("label", "未知")
                country = data.get("ipinfo", {}).get("country", "未知")
                if ip_type != "未知" or country != "未知":
                    return ip_type, country
        except Exception:
            continue
    return "查询失败", "未知"

def check_proxy(proxy, proto):
    proxies = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}
    for _ in range(MAX_RETRIES):
        try:
            resp = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT, verify=False)
            if resp.status_code == 200:
                ip = proxy.split(":")[0]
                ip_type, country = check_ip_info(ip)
                return proxy, True, ip_type, country
        except Exception:
            continue
    return proxy, False, None, None

def main():
    input_file = "https.txt"
    if len(sys.argv) > 1:
        input_file = sys.argv[1]

    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 去重
    seen = set()
    proxies = []
    for line in lines:
        ip, proto = extract_ip_port_proto(line.strip())
        if ip and ip not in seen:
            seen.add(ip)
            proxies.append((ip, proto))

    total = len(proxies)
    print(f"共找到 {total} 个唯一代理，开始验证...\n")

    results = []
    ok_count = fail_count = res_count = idc_count = 0

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_proxy, ip, proto): ip for ip, proto in proxies}
        for i, future in enumerate(as_completed(futures), 1):
            proxy, ok, ip_type, country = future.result()
            print(f"\n正在验证: {proxy}")  # 实时显示正在验证的 IP
            if ok:
                cn_country = country_to_cn(country)
                results.append((country, f"{proxy} | 类型: {ip_type} | 国家: {cn_country} ({country})"))
                ok_count += 1
                if "家庭宽带" in ip_type or "Residential" in ip_type:
                    res_count += 1
                elif "IDC" in ip_type or "机房" in ip_type:
                    idc_count += 1
            else:
                fail_count += 1

            # 实时统计
            print(f"[进度] {i}/{total} | 成功: {ok_count} | 失败: {fail_count} | 家宽: {res_count} | IDC: {idc_count}")

    # 按国家分组排序
    results.sort(key=lambda x: x[0])

    with open("valid_proxies.txt", "w", encoding="utf-8") as valid_f, \
         open("家宽.txt", "w", encoding="utf-8") as res_f, \
         open("机房ip.txt", "w", encoding="utf-8") as idc_f, \
         open("fast_proxies.txt", "w", encoding="utf-8") as fast_f:

        for country, line in results:
            valid_f.write(line + "\n")
            fast_f.write(line + "\n")
            if "家庭宽带" in line or "Residential" in line:
                res_f.write(line + "\n")
            elif "IDC" in line or "机房" in line:
                idc_f.write(line + "\n")

    # 统计结果
    summary = (
        f"📊 验证结果统计：\n"
        f"- 总代理数: {total}\n"
        f"- 存活: {ok_count}\n"
        f"- 失效: {fail_count}\n"
        f"- 家宽: {res_count}\n"
        f"- 机房: {idc_count}\n"
    )
    with open("summary.txt", "w", encoding="utf-8") as summary_f:
        summary_f.write(summary)

    print("\n✅ 验证完成，结果已写入文件。")
    print(summary)

if __name__ == "__main__":
    main()
