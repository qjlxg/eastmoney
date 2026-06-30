import requests
import re
import base64
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time

# ======================
# 配置
# ======================
BASE_URL = "https://t.me/s/freeVPNjd"
MAX_WORKERS = 10
TIMEOUT = 15

lock = Lock()
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"
})

# ======================
# 请求
# ======================
def fetch(url):
    try:
        r = session.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return ""

# ======================
# 提取子页面
# ======================
def get_sub_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]

        # Telegram 真实消息链接
        if href.startswith("/") and "freeVPNjd" in href:
            links.add("https://t.me" + href)

    return list(links)

# ======================
# base64 解码尝试
# ======================
def try_decode_base64(text):
    try:
        if len(text) < 80:
            return None

        # 补齐 padding
        padding = len(text) % 4
        if padding:
            text += "=" * (4 - padding)

        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")

        if any(x in decoded for x in ["vmess://", "vless://", "trojan://", "ss://"]):
            return decoded

    except:
        pass

    return None

# ======================
# 节点提取核心
# ======================
def parse_nodes(text):
    nodes = set()

    # 1. 直接协议节点
    nodes.update(re.findall(
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
        text
    ))

    # 2. base64块（Telegram常见）
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{60,}={0,2}', text)

    for b64 in b64_blocks:
        decoded = try_decode_base64(b64)
        if decoded:
            nodes.update(re.findall(
                r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
                decoded
            ))

    return nodes

# ======================
# 抓取单页
# ======================
def process_page(url):
    html = fetch(url)
    if not html:
        return set()

    text = BeautifulSoup(html, "html.parser").get_text()
    return parse_nodes(text)

# ======================
# 主流程
# ======================
def main():
    print("[1] 获取频道首页...")

    main_html = fetch(BASE_URL)
    if not main_html:
        print("❌ 首页获取失败")
        return

    sub_links = get_sub_links(main_html)

    print(f"[2] 发现 {len(sub_links)} 个帖子")

    if len(sub_links) == 0:
        print("❌ 没有解析到帖子链接（Telegram结构可能变化）")
        return

    print("[3] 并发抓取帖子...")

    all_nodes = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_page, url) for url in sub_links]

        for f in as_completed(futures):
            result = f.result()
            if result:
                with lock:
                    all_nodes.update(result)

    print(f"[4] 共提取节点：{len(all_nodes)}")

    if all_nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for n in sorted(all_nodes):
                f.write(n + "\n")

        print("✅ 已保存 all_nodes.txt")
    else:
        print("❌ 未提取到任何节点")

# ======================
# 入口
# ======================
if __name__ == "__main__":
    main()