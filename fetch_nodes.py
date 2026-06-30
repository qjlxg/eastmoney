import requests
import re
import time
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 目标频道
URL_LIST = ["https://t.me/s/freeVPNjd"]

def get_session():
    """创建一个带有重试机制的会话"""
    session = requests.Session()
    # 策略：如果遇到 429 或 5xx 错误，自动重试 3 次
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def fetch_url(url):
    session = get_session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Referer': 'https://t.me/'
    }
    try:
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        print(f"[SUCCESS] 成功抓取: {url} | 内容长度: {len(response.text)}")
        return response.text
    except Exception as e:
        print(f"[ERROR] 抓取失败 {url}: {str(e)}")
        return ""

def parse_nodes(text):
    # 针对各种协议的匹配规则
    patterns = [
        r'(vmess://[a-zA-Z0-9+/=]+)',
        r'(vless://[a-zA-Z0-9@:?#._-]+)',
        r'(trojan://[a-zA-Z0-9@:?#._-]+)',
        r'(ss://[a-zA-Z0-9@:?#._-]+)',
        r'(socks5://[a-zA-Z0-9@:?#._-]+)',
        r'(http://[a-zA-Z0-9@:?#._-]+)',
        r'(hysteria2://[a-zA-Z0-9@:?#._-]+)',
        r'(hysteria://[a-zA-Z0-9@:?#._-]+)',
        r'(tuic://[a-zA-Z0-9@:?#._-]+)',
        r'(anytls://[a-zA-Z0-9@:?#._-]+)'
    ]
    nodes = set()
    for p in patterns:
        matches = re.findall(p, text)
        nodes.update(matches)
    return nodes

def main():
    print("开始抓取任务...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        contents = list(executor.map(fetch_url, URL_LIST))
    
    all_nodes = set()
    for content in contents:
        if content:
            all_nodes.update(parse_nodes(content))
    
    if not all_nodes:
        print("[WARNING] 未匹配到任何节点，请检查正则或目标页面结构。")
    else:
        print(f"[INFO] 总共获取到 {len(all_nodes)} 个节点。")
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for node in sorted(all_nodes):
                f.write(node + "\n")

if __name__ == "__main__":
    main()
