import requests
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# 使用 TGStat 镜像站，避免 Cloudflare 拦截
TARGET_URL = "https://tgstat.com/channel/@freeVPNjd/archives"

def fetch_html(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Referer': 'https://tgstat.com/'
    }
    try:
        response = requests.get(url, headers=headers, timeout=20)
        return response.text if response.status_code == 200 else ""
    except Exception as e:
        print(f"抓取失败: {e}")
        return ""

def parse_content(html):
    soup = BeautifulSoup(html, 'html.parser')
    # 提取所有文本内容
    text = soup.get_text()
    
    # 正则规则：匹配订阅链接 (http/https) 和各种协议节点
    patterns = [
        r'https?://[a-zA-Z0-9./:?&_=-]+',
        r'(vmess|vless|trojan|ss|socks5|hysteria2|hysteria|tuic|anytls)://[a-zA-Z0-9@:?#._=-]+'
    ]
    
    nodes = set()
    for p in patterns:
        matches = re.findall(p, text)
        nodes.update(matches)
    return nodes

def main():
    print("开始从 TGStat 抓取节点...")
    html = fetch_html(TARGET_URL)
    if not html:
        print("未能获取页面内容。")
        return

    nodes = parse_content(html)
    
    # 过滤掉非订阅相关的链接 (如社交媒体链接)
    valid_nodes = [n for n in nodes if any(proto in n for proto in ['http', 'vmess', 'vless', 'trojan', 'ss', 'socks5', 'tuic', 'hysteria'])]
    
    if valid_nodes:
        with open("all_nodes.txt", "w", encoding="utf-8") as f:
            for node in sorted(valid_nodes):
                f.write(node + "\n")
        print(f"成功更新 {len(valid_nodes)} 个节点至 all_nodes.txt")
    else:
        print("未提取到有效节点。")

if __name__ == "__main__":
    main()
