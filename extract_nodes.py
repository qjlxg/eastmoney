import re
import os
import requests
import base64
from concurrent.futures import ThreadPoolExecutor

# 定义支持的协议列表
PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5", 
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

def get_nodes_from_url(url):
    """请求订阅链接并返回节点内容"""
    try:
        response = requests.get(url.strip(), timeout=10)
        if response.status_code == 200:
            content = response.text
            # 尝试解码 Base64 (如果订阅内容是 Base64 编码的)
            try:
                decoded = base64.b64decode(content + "==").decode('utf-8', errors='ignore')
                return decoded
            except:
                return content
    except:
        return ""
    return ""

def extract_nodes():
    if not os.path.exists("valid_subs.txt"):
        print("❌ valid_subs.txt 不存在")
        return

    with open("valid_subs.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    found_nodes = set()
    pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s<>"\']+'

    print(f"正在从 {len(urls)} 个订阅源提取节点...")

    # 并行请求所有订阅链接
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(get_nodes_from_url, urls)
        for content in results:
            if content:
                # 匹配所有符合协议的节点
                matches = re.findall(pattern, content, re.IGNORECASE)
                for m in matches:
                    found_nodes.add(m)

    # 保存到 all_nodes.txt
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for node in sorted(list(found_nodes)):
            f.write(node + "\n")
            
    print(f"✅ 提取完成，共提取 {len(found_nodes)} 个唯一节点，已保存至 all_nodes.txt")

if __name__ == "__main__":
    extract_nodes()
