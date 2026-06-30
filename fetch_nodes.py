import requests
import re
import base64
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

BASE_URL = "https://t.me/s/freeVPNjd"

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0"
})

lock = Lock()
all_nodes = set()

# ======================
# 请求
# ======================
def fetch(url):
    try:
        r = session.get(url, timeout=15)
        return r.text if r.status_code == 200 else ""
    except:
        return ""

# ======================
# 节点提取
# ======================
def extract_nodes(text):
    nodes = set()

    # 1. 直接协议
    nodes.update(re.findall(
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
        text
    ))

    # 2. base64块（增强版）
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{60,}={0,2}', text)

    for b64 in b64_blocks:
        try:
            decoded = base64.b64decode(b64 + "==", validate=False).decode("utf-8", errors="ignore")

            nodes.update(re.findall(
                r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
                decoded
            ))
        except:
            pass

    return nodes

# ======================
# 核心：直接解析 message
# ======================
def parse_page(html):
    soup = BeautifulSoup(html, "html.parser")

    messages = soup.select(".tgme_widget_message_text")

    nodes = set()

    for msg in messages:
        text = msg.get_text(separator=" ", strip=True)
        nodes.update(extract_nodes(text))

    return nodes

# ======================
# main
# ======================
def main():
    print("抓取 Telegram 页面...")

    html = fetch(BASE_URL)

    if not html:
        print("❌ 页面为空")
        return

    print("解析 messages...")

    nodes = parse_page(html)

    print(f"提取节点数量: {len(nodes)}")

    if nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for n in sorted(nodes):
                f.write(n + "\n")

        print("✅ 已保存 all_nodes.txt")
    else:
        print("❌ 没抓到节点（说明频道内容可能是图片/加密/二次渲染）")

if __name__ == "__main__":
    main()