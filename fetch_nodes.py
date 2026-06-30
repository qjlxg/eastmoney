import requests
import re
import base64
import gzip
import json
import yaml
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# =========================
# 配置
# =========================
BASE_URL = "https://t.me/s/freeVPNjd"
MAX_WORKERS = 10
TIMEOUT = 15

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
        r = session.get(url, timeout=TIMEOUT)
        return r.text if r.status_code == 200 else ""
    except:
        return ""

# =========================
# 提取订阅链接
# =========================
def extract_links(text):
    links = re.findall(r'https?://[^\s"\'<>]+', text)

    subs = []
    for l in links:
        # 过滤 Telegram 自己链接
        if "t.me" not in l:
            subs.append(l)

    return list(set(subs))

# =========================
# base64 解码
# =========================
def try_b64(text):
    try:
        if len(text) < 50:
            return None
        return base64.b64decode(text + "==").decode("utf-8", errors="ignore")
    except:
        return None

# =========================
# gzip 解码（很多订阅会用）
# =========================
def try_gzip(data):
    try:
        return gzip.decompress(data).decode("utf-8", errors="ignore")
    except:
        return None

# =========================
# 提取节点
# =========================
def extract_nodes(text):
    return set(re.findall(
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
        text
    ))

# =========================
# 智能解析订阅
# =========================
def parse_subscription(content):

    nodes = set()

    if not content:
        return nodes

    raw = content.strip()

    # ========= 1. JSON订阅 =========
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            return extract_nodes(json.dumps(data))
        except:
            pass

    # ========= 2. Clash YAML =========
    if "proxies:" in raw:
        try:
            data = yaml.safe_load(raw)
            return extract_nodes(json.dumps(data))
        except:
            pass

    # ========= 3. base64订阅 =========
    decoded = try_b64(raw)
    if decoded:
        nodes |= extract_nodes(decoded)

        # 再二次递归（订阅套订阅）
        sub_links = extract_links(decoded)
        for l in sub_links:
            sub_content = fetch(l)
            nodes |= parse_subscription(sub_content)

        return nodes

    # ========= 4. gzip订阅 =========
    try:
        gz = base64.b64decode(raw + "==", validate=False)
        decoded = try_gzip(gz)
        if decoded:
            nodes |= extract_nodes(decoded)
            return nodes
    except:
        pass

    # ========= 5. 普通文本 =========
    nodes |= extract_nodes(raw)

    return nodes

# =========================
# Telegram页面解析
# =========================
def get_page():
    return fetch(BASE_URL)

def get_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()

    return extract_links(text)

# =========================
# 处理订阅
# =========================
def process(url):
    content = fetch(url)
    return parse_subscription(content)

# =========================
# 主函数
# =========================
def main():

    print("[1] 获取 Telegram 页面...")
    html = get_page()

    print("[2] 提取订阅链接...")
    subs = get_links(html)

    print(f"[3] 找到订阅: {len(subs)}")

    if not subs:
        print("❌ 没有订阅链接")
        return

    print("[4] 开始解析订阅内容...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(process, u) for u in subs]

        for f in as_completed(futures):
            nodes = f.result()

            if nodes:
                with lock:
                    final_nodes.update(nodes)

    print(f"[5] 最终节点数量: {len(final_nodes)}")

    if final_nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for n in sorted(final_nodes):
                f.write(n + "\n")

        print("✅ 已保存 all_nodes.txt")
    else:
        print("❌ 仍然没有解析出节点（说明订阅被加密/图片化/风控）")

if __name__ == "__main__":
    main()