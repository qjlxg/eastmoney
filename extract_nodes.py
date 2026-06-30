import re, os, requests, base64, yaml, json, socket
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5",
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# requests session（关键优化）
# ----------------------------
session = requests.Session()
retry = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[500, 502, 503, 504]
)
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))

# ----------------------------
# base64 decode（强化版）
# ----------------------------
def b64_decode(data: str) -> str:
    data = data.strip()
    data = data.replace('-', '+').replace('_', '/') # 处理urlsafe
    data += "=" * (-len(data) % 4)

    for func in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return func(data).decode("utf-8", "ignore")
        except:
            continue
    return ""

# ----------------------------
# 拉取订阅
# ----------------------------
def get_nodes_from_url(url):
    try:
        r = session.get(url.strip(), timeout=10)
        if r.status_code != 200:
            return ""

        content = r.text.strip()
        decoded = b64_decode(content)
        return decoded or content
    except:
        return ""

# ----------------------------
# node解析（补充了对各协议的详细解析逻辑）
# ----------------------------
def parse_node(node):
    try:
        # VMess 解析
        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            j = json.loads(raw)
            return {
                "name": j.get("ps", "vmess"),
                "type": "vmess",
                "server": j.get("add"),
                "port": int(j.get("port", 0)),
                "uuid": j.get("id"),
                "alterId": int(j.get("aid", 0)),
                "cipher": "auto",
                "udp": True
            }

        # URL 格式解析 (Trojan, VLESS, SS, HY2, TUIC)
        u = urlparse(node)
        proto = u.scheme.lower()
        
        if proto in PROTOCOLS:
            name = unquote(u.fragment) if u.fragment else f"{proto}_{hash(node) % 10000}"
            # 基础结构
            res = {
                "name": name,
                "type": proto if proto != "hysteria2" else "hysteria2",
                "server": u.hostname,
                "port": int(u.port) if u.port else 443,
            }

            # 协议特定字段处理
            if proto == "ss":
                # ss://base64(method:password)@host:port
                if "@" not in u.netloc:
                    user_info = b64_decode(u.username).split(":")
                    res["cipher"] = user_info[0]
                    res["password"] = user_info[1]
                else:
                    res["cipher"] = u.username
                    res["password"] = u.password
            elif proto in ["trojan", "vless", "hysteria2", "hy2", "tuic"]:
                res["password"] = u.username or u.netloc.split('@')[0]
                if proto == "vless":
                    res["uuid"] = res.pop("password")
                    res["udp"] = True
                if proto == "hysteria2" or proto == "hy2":
                    res["type"] = "hysteria2"
            
            return res

    except Exception:
        return None

# ----------------------------
# 主流程
# ----------------------------
def extract_nodes():
    if not os.path.exists("valid_subs.txt"):
        print("❌ 错误：找不到 valid_subs.txt")
        return

    urls = [i.strip() for i in open("valid_subs.txt", encoding="utf-8") if i.strip()]
    pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s<>"\']+'
    
    raw_nodes = set()

    # 并行抓取内容
    print(f"正在从 {len(urls)} 个订阅源抓取节点...")
    with ThreadPoolExecutor(max_workers=8) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if not content:
                continue
            # 提取符合协议格式的链接
            matches = re.findall(pattern, content, re.IGNORECASE)
            raw_nodes.update(matches)

    proxies = []
    seen_names = set()
    seen_endpoints = set() # 用于物理去重 (server+port)

    for n in raw_nodes:
        p = parse_node(n)
        if not p or not p.get("server") or not p.get("port"):
            continue
            
        # 物理去重：地址 + 端口
        endpoint = f"{p['server']}:{p['port']}"
        if endpoint in seen_endpoints:
            continue
            
        # 名称去重
        if p["name"] in seen_names:
            p["name"] = f"{p['name']}_{hash(endpoint) % 100}"
            
        seen_names.add(p["name"])
        seen_endpoints.add(endpoint)
        proxies.append(p)

    if not proxies:
        print("⚠️ 未找到有效节点")
        return

    # 读取模板
    if not os.path.exists("rules.yaml"):
        print("❌ 错误：找不到 rules.yaml 模板")
        return

    with open("rules.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # 安全 merge
    config.setdefault("proxies", [])
    config["proxies"].extend(proxies)

    # 最终去重（按 name）
    uniq = {p["name"]: p for p in config["proxies"]}
    config["proxies"] = list(uniq.values())

    # 更新 proxy-groups
    proxy_names = [p["name"] for p in proxies]
    if "proxy-groups" in config:
        for group in config.get("proxy-groups", []):
            # 仅向指定组注入节点
            if group.get("name") in ["自动优选", "节点选择", "负载均衡"]:
                existing = group.get("proxies", [])
                # 合并并保持唯一性
                group["proxies"] = list(dict.fromkeys(existing + proxy_names))

    # 写入文件
    with open("all_nodes.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 完成：新增 {len(proxies)} 个节点，总计 {len(config['proxies'])} 个节点已写入 all_nodes.yaml")

if __name__ == "__main__":
    extract_nodes()
