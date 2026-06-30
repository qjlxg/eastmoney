import re, os, requests, base64, yaml, json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# 定义所有支持的协议
PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5", "vless", 
    "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# 辅助函数
# ----------------------------
def b64_decode(data: str) -> str:
    data = data.strip()
    data += "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", "ignore")
    except:
        try: return base64.b64decode(data).decode("utf-8", "ignore")
        except: return ""

def get_nodes_from_url(url):
    try:
        r = requests.get(url.strip(), timeout=12)
        if r.status_code != 200: return ""
        content = r.text.strip()
        decoded = b64_decode(content)
        return decoded if decoded else content
    except: return ""

# ----------------------------
# 核心解析逻辑
# ----------------------------
def parse_node(node):
    try:
        # vmess
        if node.startswith("vmess://"):
            data = b64_decode(node[8:])
            j = json.loads(data)
            return {"name": j.get("ps", "vmess"), "type": "vmess", "server": j.get("add"), "port": int(j.get("port", 0)), "uuid": j.get("id")}
        
        # trojan
        if node.startswith("trojan://"):
            u = urlparse(node)
            return {"name": u.fragment or "trojan", "type": "trojan", "server": u.hostname, "port": u.port, "password": u.username}
        
        # vless
        if node.startswith("vless://"):
            u = urlparse(node)
            return {"name": u.fragment or "vless", "type": "vless", "server": u.hostname, "port": u.port, "uuid": u.username}

        # 其余协议：保留 raw 字段以确保 Clash 配置兼容性
        if node.startswith(tuple([f"{p}://" for p in PROTOCOLS])):
            proto = node.split("://")[0]
            return {"name": f"{proto}_{node[-6:]}", "type": proto, "raw": node}
            
    except: return None
    return None

# ----------------------------
# 主逻辑
# ----------------------------
def extract_nodes():
    if not os.path.exists("valid_subs.txt"): return
    urls = [i.strip() for i in open("valid_subs.txt", encoding="utf-8") if i.strip()]

    raw_nodes = set()
    # 动态构建匹配所有协议的正则
    pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s<>"\']+'

    with ThreadPoolExecutor(max_workers=10) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if not content: continue
            for m in re.findall(pattern, content, re.IGNORECASE):
                raw_nodes.add(m)

    proxies = [p for p in [parse_node(n) for n in raw_nodes] if p]
    proxy_names = [p["name"] for p in proxies]

    # 注入到 rules.yaml 配置模板
    if os.path.exists("rules.yaml"):
        with open("rules.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        config["proxies"] = proxies
        
        # 自动更新代理组
        for group in config.get("proxy-groups", []):
            if group["name"] in ["自动优选", "节点选择"]:
                existing = [p for p in group.get("proxies", []) if p not in proxy_names and p not in ["手动切换", "自动优选", "节点选择", "DIRECT"]]
                group["proxies"] = proxy_names + ["手动切换", "DIRECT"] + existing

        with open("all_nodes.yaml", "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
            
    print(f"✅ 完成：已更新 all_nodes.yaml，共注入 {len(proxies)} 个节点")

if __name__ == "__main__":
    extract_nodes()
