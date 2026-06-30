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
final_nodes = set()

# =========================
# 请求
# =========================
def fetch(url):
    try:
        r = session.get(url, timeout=15)
        return r.text if r.status_code == 200 else ""
    except:
        return ""

# =========================
# Step1：提取订阅链接
# =========================
def extract_sub_links(text):
    return set(re.findall(r'https?://[^\s"\'<>]+', text))

# =========================
# Step2：解析节点
# =========================
def parse_nodes(text):
    nodes = set()

    # 直接节点
    nodes.update(re.findall(
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
        text
    ))

    # base64（可选）
    b64s = re.findall(r'[A-Za-z0-9+/]{60,}={0,2}', text)

    for b64 in b64s:
        try:
            decoded = base64.b64decode(b64 + "==", validate=False).decode("utf-8", errors="ignore")
            nodes.update(re.findall(
                r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
                decoded
            ))
        except:
            pass

    return nodes

# =========================
# Step3：处理订阅链接
# =========================
def process_sub(url):
    content = fetch(url)
    if not content:
        return set()

    return parse_nodes(content)

# =========================
# 主流程
# =========================
def main():
    print("[1] 获取 Telegram 页面...")

    html = fetch(BASE_URL)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()

    print("[2] 提取订阅链接...")

    links = extract_sub_links(text)

    # ⚠️ 过滤 Telegram 自己的链接
    subs = [x for x in links if x.startswith("http") and "t.me" not in x]

    print(f"[3] 找到订阅链接: {len(subs)}")

    if not subs:
        print("❌ 没有找到外部订阅链接")
        return

    print("[4] 并发抓取订阅内容...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(process_sub, subs)

        for nodes in results:
            with lock:
                final_nodes.update(nodes)

    print(f"[5] 总节点数量: {len(final_nodes)}")

    if final_nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for n in sorted(final_nodes):
                f.write(n + "\n")

        print("✅ 已保存 all_nodes.txt")
    else:
        print("❌ 订阅内容里仍然没有节点")

if __name__ == "__main__":
    main()