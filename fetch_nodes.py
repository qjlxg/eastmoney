import requests
import re
import base64
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# 目标源
TARGET_URL = "https://tgstat.com/channel/@freeVPNjd/archives"

def fetch_content(url):
    """通用请求函数"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        res = requests.get(url, headers=headers, timeout=10)
        return res.text if res.status_code == 200 else ""
    except:
        return ""

def decode_node(content):
    """尝试解码Base64内容"""
    try:
        # 如果内容是Base64，尝试解码
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        return decoded
    except:
        return content

def parse_nodes():
    # 1. 抓取目录页
    html = fetch_content(TARGET_URL)
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text()
    
    # 2. 提取所有链接
    all_links = re.findall(r'https?://[a-zA-Z0-9./:?&_=-]+', text)
    
    final_nodes = set()
    protocols = ('vmess://', 'vless://', 'trojan://', 'ss://', 'socks5://', 'hysteria2://', 'tuic://', 'anytls://')

    def process_link(url):
        # 排除明显的非节点网页
        if any(x in url for x in ['t.me', 'w3.org', 'google', 'twitter', 'facebook']):
            return
        
        content = fetch_content(url)
        content = decode_node(content)
        
        # 提取内容中的协议节点
        matches = re.findall(r'[a-zA-Z0-9]+://[a-zA-Z0-9@:?#._=-]+', content)
        for m in matches:
            if m.lower().startswith(protocols):
                final_nodes.add(m)

    # 3. 并行处理提取到的链接（深度抓取）
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process_link, list(set(all_links)))
    
    return final_nodes

if __name__ == "__main__":
    nodes = parse_nodes()
    if nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for node in sorted(nodes):
                f.write(node + "\n")
        print(f"成功获取 {len(nodes)} 个节点。")
    else:
        print("未提取到有效节点。")
