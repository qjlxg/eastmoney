import re
import os
from concurrent.futures import ThreadPoolExecutor

# 定义支持的协议列表
PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5", 
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

def process_line(line):
    """从单行文本中提取匹配协议的节点"""
    pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s<>"\']+'
    return re.findall(pattern, line, re.IGNORECASE)

def extract_nodes():
    if not os.path.exists("valid_subs.txt"):
        print("❌ valid_subs.txt 不存在")
        return

    found_nodes = set()
    
    with open("valid_subs.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 使用线程池并行处理每一行，对于大规模订阅列表可显著提升速度
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(process_line, lines)
        for nodes in results:
            for node in nodes:
                found_nodes.add(node) # set 自动完成去重

    # 保存到 all_nodes.txt
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for node in sorted(list(found_nodes)):
            f.write(node + "\n")
            
    print(f"✅ 提取完成，共提取 {len(found_nodes)} 个唯一节点，已保存至 all_nodes.txt")

if __name__ == "__main__":
    extract_nodes()
