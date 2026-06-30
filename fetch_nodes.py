import requests
import re
import base64
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# =========================
# 配置
# =========================
BASE_URL = "https://t.me/s/freeVPNjd"
MAX_WORKERS = 10
TIMEOUT = 15

# 排除列表
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com'
]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})

lock = Lock()
valid_subs = set()

# =========================
# 请求
# =========================
def fetch(url):
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except:
        return 0, ""

# =========================
# 内容校验函数
# =========================
def is_valid_sub_content(content):
    """
    判断返回内容是否为有效的订阅数据
    """
    content = content.strip()
    if not content:
        return False
    
    # 检查是否为 Clash 配置 (YAML)
    if "proxies:" in content or "proxy-groups:" in content:
        return True

    # 尝试检查 Base64
    try:
        # 补全 padding 以防解码失败
        padding = (4 - len(content) % 4) % 4
        decoded = base64.b64decode(content + "=" * padding, validate=True).decode('utf-8', errors='ignore')
        if any(scheme in decoded for scheme in ['vmess://', 'ss://', 'vless://', 'trojan://', 'ssr://']):
            return True
    except:
        pass
    
    # 检查是否为普通的节点列表
    if any(content.startswith(scheme) for scheme in ['vmess://', 'ss://', 'vless://', 'trojan://', 'ssr://']):
        return True

    return False

# =========================
# 提取并清理订阅链接
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()

    # 匹配 http/https 开头，直到遇到中文、空格、引号、尖括号等
    urls = re.findall(r'https?://[^\s\u4e00-\u9fa5"\'<>]+', text)

    subs = []
    for u in urls:
        # 去掉链接末尾可能存在的标点或特殊字符
        clean_url = re.sub(r'[^\w/:.-]+$', '', u)
        
        # 检查黑名单
        if any(domain in clean_url for domain in BLACKLIST_DOMAINS):
            continue
            
        subs.append(clean_url)

    return list(set(subs))

# =========================
# 处理订阅
# =========================
def process(url):
    code, content = fetch(url)
    if code == 200 and is_valid_sub_content(content):
        return url
    return None

# =========================
# 主流程
# =========================
def main():
    print("[1] 获取 Telegram 页面...")
    code, html = fetch(BASE_URL)
    if code != 200:
        print("❌ Telegram页面获取失败")
        return

    print("[2] 提取并清洗订阅链接...")
    subs = extract_links(html)
    print(f"[3] 发现订阅: {len(subs)}")

    if not subs:
        print("❌ 没有订阅链接")
        return

    print("[4] 检测订阅有效性...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(process, u) for u in subs]
        for f in as_completed(futures):
            result = f.result()
            if result:
                with lock:
                    valid_subs.add(result)

    print(f"[5] 有效订阅数量: {len(valid_subs)}")

    if valid_subs:
        with open("valid_subs.txt", "w", encoding="utf-8") as f:
            for u in sorted(valid_subs):
                f.write(u + "\n")
        print("✅ 已保存 valid_subs.txt")
    else:
        print("❌ 没有有效订阅")

if __name__ == "__main__":
    main()
