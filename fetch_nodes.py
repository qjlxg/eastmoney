import requests
import base64
import re
import yaml
from concurrent.futures import ThreadPoolExecutor

# 你的频道地址或数据源
CHANNEL_URL = "https://t.me/s/freeVPNjd" 

def decode_base64(data):
    try:
        padding = '=' * (4 - len(data) % 4)
        return base64.b64decode(data + padding).decode('utf-8', errors='ignore')
    except:
        return ""

def fetch_and_parse():
    # 这里的逻辑需要根据实际页面内容调整，通常是抓取页面中所有的链接
    response = requests.get(CHANNEL_URL, timeout=15)
    content = response.text
    
    # 使用正则表达式提取可能的订阅链接/节点明文
    # 匹配各种协议的正则
    patterns = [
        r'(vmess://[a-zA-Z0-9+/=]+)',
        r'(vless://[a-zA-Z0-9@:?#]+)',
        r'(trojan://[a-zA-Z0-9@:?#]+)',
        r'(ss://[a-zA-Z0-9@:?#]+)',
        r'(hysteria2://[a-zA-Z0-9@:?#]+)',
        r'(tuic://[a-zA-Z0-9@:?#]+)'
    ]
    
    nodes = set()
    for p in patterns:
        nodes.update(re.findall(p, content))
    
    return nodes

def save_nodes(nodes):
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for node in sorted(list(nodes)):
            f.write(node + "\n")

if __name__ == "__main__":
    nodes = fetch_and_parse()
    save_nodes(nodes)
