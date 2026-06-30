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
session.headers.update({"User-Agent": "Mozilla/5.0"})

lock = Lock()
valid_subs = set()

# =========================
# 请求与校验
# =========================
def fetch(url):
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except:
        return 0, ""

def is_valid_sub_content(content):
    content = content.strip()
    if not content or len(content) < 50: return False
    
    if "proxies:" in content or "proxy-groups:" in content: return True
    
    try:
        # 处理可能的 Base64 编码
        padding = (4 - len(content) % 4) % 4
        decoded = base64.b64decode(content + "=" * padding, validate=False).decode('utf-8', errors='ignore')
        if any(s in decoded for s in ['vmess://', 'ss://', 'vless://', 'trojan://', 'ssr://']): return True
    except: pass
    
    if any(content.startswith(s) for s in ['vmess://', 'ss://', 'vless://', 'trojan://', 'ssr://']): return True
    return False

# =========================
# 针对性提取逻辑 (适配 1000012088.jpg)
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()
    
    # 核心：精准匹配“订阅链接：”后的 URL，直到遇到非 URL 字符
    urls = re.findall(r'订阅链接[:：]\s*(https?://[^\s\u4e00-\u9fa5]+)', text)
    
    clean_subs = []
    for u in urls:
        # 再次清洗末尾可能残留的特殊标点
        clean_url = re.sub(r'[^\w/:.-]+$', '', u)
        if not any(domain in clean_url for domain in BLACKLIST_DOMAINS):
            clean_subs.append(clean_url)
    return list(set(clean_subs))

def process(url):
    code, content = fetch(url)
    return url if code == 200 and is_valid_sub_content(content) else None

# =========================
# 主流程
# =========================
def main():
    print("[1] 获取频道内容...")
    code, html = fetch(BASE_URL)
    if code != 200: return

    print("[2] 提取链接...")
    subs = extract_links(html)
    
    print(f"[3] 检测中，发现链接数: {len(subs)}")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(process, u) for u in subs]
        for f in as_completed(futures):
            res = f.result()
            if res:
                with lock: valid_subs.add(res)

    if valid_subs:
        with open("valid_subs.txt", "w", encoding="utf-8") as f:
            for u in sorted(valid_subs): f.write(u + "\n")
        print(f"✅ 保存成功，共 {len(valid_subs)} 个有效订阅")

if __name__ == "__main__":
    main()
