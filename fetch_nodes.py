import requests
import re
import base64
import gzip
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
# 提取订阅链接
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()

    urls = re.findall(r'https?://[^\s"\'<>]+', text)

    subs = []
    for u in urls:
        if "t.me" not in u:
            subs.append(u)

    return list(set(subs))

# =========================
# 判断订阅是否有效
# =========================
def is_valid_subscription(content):

    if not content:
        return False

    # 1. 明显错误页面
    if "404" in content.lower():
        return False

    if "forbidden" in content.lower():
        return False

    if len(content) < 50:
        return False

    # 2. base64订阅判断
    try:
        decoded = base64.b64decode(content + "==", validate=False).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return True
    except:
        pass

    # 3. clash订阅
    if "proxies:" in content or "proxy-groups:" in content:
        return True

    # 4. vmess/vless直链
    if "vmess://" in content or "vless://" in content or "trojan://" in content:
        return True

    return False

# =========================
# 处理订阅
# =========================
def process(url):

    code, content = fetch(url)

    if code != 200:
        return None

    # 不管是不是有效期，只要请求成功，都返回url
    return url

# =========================
# 主流程
# =========================
def main():

    print("[1] 获取 Telegram 页面...")

    code, html = fetch(BASE_URL)

    if code != 200:
        print("❌ Telegram页面获取失败")
        return

    print("[2] 提取订阅链接...")

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
