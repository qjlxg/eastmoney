import re, os, requests, base64, yaml, json
from urllib.parse import urlparse
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
    data += "=" * (-len(data) % 4)

    for func in (base64.urlsafe_b64decode, base64.b64decode):
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
# node解析
# ----------------------------
def parse_node(node):
    try:
        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            j = json.loads(raw)
            return {
                "name": j.get("ps", "vmess"),
                "type": "vmess",
                "server": j.get("add"),
                "port": int(j.get("port", 0)),
                "uuid": j.get("id")
            }

        if node.startswith("trojan://"):
            u = urlparse(node)
            return {
                "name": u.fragment or "trojan",
                "type": "trojan",
                "server": u.hostname,
                "port": u.port,
                "password": u.username
            }

        if node.startswith("vless://"):
            u = urlparse(node)
            return {
                "name": u.fragment or "vless",
                "type": "vless",
                "server": u.hostname,
                "port": u.port,
                "uuid": u.username
            }

        if any(node.startswith(p + "://") for p in PROTOCOLS):
            proto = node.split("://")[0]
            return {
                "name": f"{proto}_{hash(node) % 10000}",
                "type": proto,
                "raw": node
            }

    except:
        return None

# ----------------------------
# 主流程
# ----------------------------
def extract_nodes():
    if not os.path.exists("valid_subs.txt"):
        return

    urls = [i.strip() for i in open("valid_subs.txt", encoding="utf-8") if i.strip()]

    pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s<>"\']+'

    raw_nodes = set()

    with ThreadPoolExecutor(max_workers=8) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if not content:
                continue
            raw_nodes.update(re.findall(pattern, content, re.IGNORECASE))

    proxies = []
    seen = set()

    for n in raw_nodes:
        p = parse_node(n)
        if not p:
            continue
        if p["name"] in seen:
            continue
        seen.add(p["name"])
        proxies.append(p)

    proxy_names = [p["name"] for p in proxies]

    if not os.path.exists("rules.yaml"):
        return

    with open("rules.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # 安全 merge（不覆盖）
    config.setdefault("proxies", [])
    config["proxies"].extend(proxies)

    # 去重 proxies（按 name）
    uniq = {p["name"]: p for p in config["proxies"]}
    config["proxies"] = list(uniq.values())

    # 更新 group（防重复）
    for group in config.get("proxy-groups", []):
        if group.get("name") in ["自动优选", "节点选择"]:
            base = [p for p in proxy_names if p not in group.get("proxies", [])]
            group["proxies"] = list(dict.fromkeys(group.get("proxies", []) + base))

    with open("all_nodes.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 完成：{len(proxies)} 个节点已写入 all_nodes.yaml")

if __name__ == "__main__":
    extract_nodes()