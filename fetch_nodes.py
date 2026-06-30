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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
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
# 提取外部订阅链接
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()

    urls = re.findall(r'https?://[^\s"\'<>]+', text)

    subs = []
    for u in urls:
        # 过滤 telegram 自身
        if "t.me" not in u:
            subs.append(u)

    return list(set(subs))

# =========================
# 节点提取（核心）
# =========================
def extract_nodes(text):
    return set(re.findall(
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[^\s\'"<>]+',
        text
    ))

# =========================
# base64 解码
# =========================
def decode_base64(text):
    try:
        return base64.b64decode(text + "==", validate=False).decode("utf-8", errors="ignore")
    except:
        return None

# =========================
# gzip 解码
# =========================
def decode_gzip(data):
    try:
        return gzip.decompress(data).decode("utf-8", errors="ignore")
    except:
        return None

# =========================
# 订阅解析（万能）
# =========================
def parse_subscription(content):

    if not content:
        return set()

    content = content.strip()

    nodes = set()

    # =========================
    # JSON订阅
    # =========================
    if content.startswith("{"):
        try:
            data = json.loads(content)
            return extract_nodes(json.dumps(data))
        except:
            pass

    # =========================
    # Clash YAML订阅
    # =========================
    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            return extract_nodes(json.dumps(data))
        except:
            pass

    # =========================
    # base64订阅（最常见）
    # =========================
    decoded = decode_base64(content)
    if decoded:
        nodes |= extract_nodes(decoded)

        # 递归：订阅套订阅
        links = re.findall(r'https?://[^\s"\'<>]+', decoded)
        for l in links:
            sub = fetch(l)
            nodes |= parse_subscription(sub)

        return nodes

    # =========================
    # gzip订阅（少见但存在）
    # =========================
    try:
        raw = base64.b64decode(content + "==", validate=False)
        decoded = decode_gzip(raw)
        if decoded:
            nodes |= extract_nodes(decoded)
            return nodes
    except:
        pass

    # =========================
    # 纯文本
    # =========================
    nodes |= extract_nodes(content)

    return nodes

# =========================
# 处理单个订阅
# =========================
def process(url):
    content = fetch(url)
    return parse_subscription(content)

# =========================
# 主流程
# =========================
def main():

    print("[1] 获取Telegram页面...")
    html = fetch(BASE_URL)

    if not html:
        print("❌ 页面获取失败")
        return

    print("[2] 提取订阅链接...")
    subs = extract_links(html)

    print(f"[3] 订阅数量: {len(subs)}")

    if not subs:
        print("❌ 没有找到外链订阅")
        return

    print("[4] 开始解析订阅...")

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
        print("❌ 仍然为0：说明订阅可能是加密/图片/JS接口")

if __name__ == "__main__":
    main()