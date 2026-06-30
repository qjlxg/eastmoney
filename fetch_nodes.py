import requests
import re
import base64
import yaml  # 需要安装: pip install pyyaml
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urlparse

# =========================
# 配置
# =========================
BASE_URL = "https://t.me/s/freeVPNjd"
MAX_WORKERS = 15
TIMEOUT = 10

# 排除列表：这些域名肯定不是订阅链接
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com'
]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
})

lock = Lock()
valid_subs = set()

# =========================
# 辅助函数：内容校验
# =========================
def is_valid_sub_content(content):
    """
    判断返回内容是否为有效的订阅数据
    1. 尝试 Base64 解码 (V2Ray/Trojan 常用)
    2. 检查是否包含 Clash 关键字
    """
    content = content.strip()
    if not content:
        return False
    
    # 检查是否为 Clash 配置 (YAML)
    if "proxies:" in content or "proxy-groups:" in content:
        return True

    # 尝试检查 Base64 (通常节点列表以 vmess://, ss:// 等开头)
    try:
        # Base64 长度通常是 4 的倍数，这里做个初步过滤
        decoded = base64.b64decode(content, validate=True).decode('utf-8')
        if any(scheme in decoded for scheme in ['vmess://', 'ss://', 'vless://', 'trojan://', 'ssr://']):
            return True
    except:
        pass
    
    # 检查是否为普通的 SIP002 (明文节点列表)
    if content.startswith('vmess://') or content.startswith('ss://'):
        return True

    return False

# =========================
# 请求
# =========================
def fetch(url):
    try:
        # 禁用代理，防止本地环境干扰，或者根据需要配置代理
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except:
        return 0, ""

# =========================
# 提取并清理订阅链接
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    # Telegram 频道消息通常在 tgme_widget_message_text 类中
    message_elements = soup.find_all(class_="tgme_widget_message_text")
    
    raw_links = []
    for msg in message_elements:
        # 1. 从 a 标签提取
        for a in msg.find_all('a', href=True):
            raw_links.append(a['href'])
        
        # 2. 从文本中匹配 (防止有的链接没被识别为 a 标签)
        text_urls = re.findall(r'https?://[^\s\u4e00-\u9fa5"\'<>]+', msg.get_text())
        raw_links.extend(text_urls)

    clean_subs = []
    for u in set(raw_links):
        # 清理末尾干扰字符
        u = re.sub(r'[^\w/:.=%&\-?]+$', '', u)
        
        # 过滤黑名单域名
        parsed = urlparse(u)
        domain = parsed.netloc.lower()
        
        if any(b in domain for b in BLACKLIST_DOMAINS):
            continue
            
        if u.startswith("http"):
            clean_subs.append(u)

    return list(set(clean_subs))

# =========================
# 核心处理：验证订阅有效性
# =========================
def process(url):
    print(f"  [验证中] {url[:50]}...")
    code, content = fetch(url)
    
    if code == 200 and is_valid_sub_content(content):
        return url
    return None

# =========================
# 主流程
# =========================
def main():
    print(f"[*] 正在获取 Telegram 页面: {BASE_URL}")
    code, html = fetch(BASE_URL)
    if code != 200 or not html:
        print("❌ 无法访问 Telegram 页面，请检查网络（可能需要科学上网）")
        return

    print("[*] 正在提取潜在订阅链接...")
    subs = extract_links(html)
    print(f"[*] 发现 {len(subs)} 个候选链接。")

    if not subs:
        print("❌ 未找到任何链接")
        return

    print(f"[*] 开始多线程验证 (线程数: {MAX_WORKERS})...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(process, u): u for u in subs}
        for f in as_completed(futures):
            result = f.result()
            if result:
                with lock:
                    valid_subs.add(result)
                    print(f"  [✅ 有效] {result}")

    print("-" * 30)
    print(f"[总结] 总计发现有效订阅: {len(valid_subs)}")

    if valid_subs:
        file_name = "valid_subs.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            for u in sorted(valid_subs):
                f.write(u + "\n")
        print(f"✅ 结果已保存至: {file_name}")
    else:
        print("❌ 未发现任何包含有效节点数据的订阅链接。")

if __name__ == "__main__":
    main()
