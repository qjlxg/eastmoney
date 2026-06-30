import requests
import re
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup  # 建议安装：pip install beautifulsoup4

# 目标频道
BASE_URL = "https://t.me/s/freeVPNjd"

def get_session():
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    })
    return session

def fetch_page(url):
    try:
        response = get_session().get(url, timeout=15)
        return response.text
    except:
        return ""

def get_sub_links(html):
    """从目录页提取所有文章链接"""
    soup = BeautifulSoup(html, 'html.parser')
    # Telegram 频道消息的链接通常包含 /s/freeVPNjd/123 格式
    links = set()
    for a in soup.find_all('a', href=True):
        if '/s/freeVPNjd/' in a['href'] and len(a['href'].split('/')) > 4:
            # 补全完整链接
            full_url = "https://t.me" + a['href']
            links.add(full_url)
    return list(links)

def parse_nodes(text):
    # 扩大匹配范围，涵盖明文节点和Base64块
    patterns = [
        r'(vmess|vless|trojan|ss|socks5|http|hysteria2|hysteria|tuic|anytls)://[a-zA-Z0-9@:?#._=-]+',
        r'([a-zA-Z0-9+/]{20,}=+)' # 捕获可能的Base64编码节点块
    ]
    nodes = set()
    for p in patterns:
        nodes.update(re.findall(p, text))
    return nodes

def main():
    # 1. 获取目录页
    print("正在抓取目录页...")
    main_html = fetch_page(BASE_URL)
    sub_links = get_sub_links(main_html)
    print(f"找到 {len(sub_links)} 个详情页，开始并行抓取...")

    # 2. 并行抓取所有详情页
    with ThreadPoolExecutor(max_workers=10) as executor:
        pages = list(executor.map(fetch_page, sub_links))
    
    # 3. 提取所有节点
    all_nodes = set()
    for page in pages:
        all_nodes.update(parse_nodes(page))
    
    # 4. 保存结果
    if all_nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for node in sorted(all_nodes):
                f.write(node + "\n")
        print(f"成功保存 {len(all_nodes)} 个节点。")
    else:
        print("未抓取到节点，请检查正则匹配或网站结构变化。")

if __name__ == "__main__":
    main()
