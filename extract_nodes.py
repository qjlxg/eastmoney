import re, os, requests, base64, yaml, json, socket, hashlib, sys
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 确保脚本在定时任务中能正确读取相对路径文件
os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5",
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# requests session
# ----------------------------
session = requests.Session()
retry = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[500, 502, 503, 504]
)
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))

def b64_decode(data: str) -> str:
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    for func in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return func(data).decode("utf-8", "ignore")
        except:
            continue
    return ""

def get_nodes_from_url(url):
    try:
        r = session.get(url.strip(), timeout=(5, 10))
        if r.status_code != 200: return ""
        content = r.text.strip()
        decoded = b64_decode(content)
        return decoded if any(p + "://" in decoded.lower() for p in PROTOCOLS) else content
    except: return ""

# ----------------------------
# node解析（重点：结构化 Reality 选项与增强 SS 解析）
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
                "uuid": j.get("id"),
                "alterId": int(j.get("aid", 0)),
                "cipher": "auto",
                "tls": True if j.get("tls") == "tls" else False,
                "udp": True
            }

        u = urlparse(node)
        proto = u.scheme.lower()
        if proto in PROTOCOLS:
            query = parse_qs(u.query)
            params = {k: v[0] for k, v in query.items()}
            
            # 使用SHA256截取保证名称一致性
            stable_hash = hashlib.sha256(node.encode()).hexdigest()[:6]
            name = unquote(u.fragment) if u.fragment else f"{proto}_{stable_hash}"
            res = {
                "name": name,
                "type": proto,
                "server": u.hostname,
                "port": int(u.port) if u.port else 443,
            }

            if proto == "ss":
                if "@" in u.netloc:
                    res["cipher"], res["password"] = u.username, u.password
                else:
                    decoded = b64_decode(u.username)
                    if ":" in decoded:
                        cipher, password = decoded.split(":", 1)
                        res["cipher"], res["password"] = cipher, password
                    else: return None
            
            elif proto == "vless":
                res["uuid"] = u.username
                res["udp"] = True
                if params.get("security") in ["tls", "reality"]:
                    res["tls"] = True
                    res["sni"] = params.get("sni", u.hostname)
                    if "flow" in params:
                        res["flow"] = params["flow"]
                    if params.get("security") == "reality":
                        res["reality-opts"] = {
                            "public-key": params.get("pbk", ""),
                            "short-id": params.get("sid", ""),
                            "fingerprint": params.get("fp", "chrome")
                        }

            elif proto == "trojan":
                res["password"] = u.username
                res["udp"] = True
                res["sni"] = params.get("sni", u.hostname)
                res["tls"] = True

            elif proto in ["hysteria2", "hy2"]:
                res["type"] = "hysteria2"
                res["password"] = u.username
            
            else:
                if u.username: res["username"] = u.username
                if u.password: res["password"] = u.password

            return res
    except Exception: return None

# ----------------------------
# 主流程
# ----------------------------
def extract_nodes():
    if not os.path.exists("valid_subs.txt"): return
    urls = [i.strip() for i in open("valid_subs.txt", encoding="utf-8") if i.strip()]
    
    raw_nodes = set()
    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                chunks = content.split()
                raw_nodes.update(c for c in chunks if any(p in c for p in PROTOCOLS) and "://" in c)

    proxies, seen_names, seen_fingerprints = [], set(), set()

    for n in raw_nodes:
        p = parse_node(n)
        if not p or not p.get("server"): continue
        
        cred = p.get("uuid") or p.get("password") or ""
        fingerprint = hashlib.md5(
            json.dumps({
                "s": p["server"],
                "p": p["port"],
                "c": cred,
                "t": p.get("type"),
                "sni": p.get("sni"),
            }, sort_keys=True).encode()
        ).hexdigest()
        
        if fingerprint in seen_fingerprints: continue
            
        if p["name"] in seen_names:
            p["name"] = f"{p['name']}_{hash(fingerprint) % 1000}"
            
        seen_names.add(p["name"])
        seen_fingerprints.add(fingerprint)
        proxies.append(p)

    if not proxies or not os.path.exists("rules.yaml"): return

    with open("rules.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    config.setdefault("proxies", [])
    config["proxies"].extend(proxies)
    config["proxies"] = list({p["name"]: p for p in config["proxies"]}.values())

    proxy_names = [p["name"] for p in proxies]
    for group in config.get("proxy-groups", []):
        if group.get("name") in ["自动优选", "节点选择", "负载均衡"]:
            group["proxies"] = list(dict.fromkeys(group.get("proxies", []) + proxy_names))

    with open("all_nodes.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000)

    print(f"✅ 完成：本次抓取 {len(proxies)} 个，总库共 {len(config['proxies'])} 个节点已写入 all_nodes.yaml")

if __name__ == "__main__":
    extract_nodes()
