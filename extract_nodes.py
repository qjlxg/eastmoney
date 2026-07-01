import re, os, requests, base64, json, hashlib, yaml
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 确保工作目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROTOCOLS = ["vmess", "trojan", "http", "ss", "socks5", "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"]

session = requests.Session()
retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))
session.headers.update({"User-Agent": "v2rayN/6.23"})

def b64_decode(data: str) -> str:
    if not data: return ""
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    try: return base64.b64decode(data).decode("utf-8", "ignore")
    except: return ""

def parse_clash_proxies(content):
    try:
        data = yaml.safe_load(content)
        if not data or "proxies" not in data: return []
        uris = []
        for p in data["proxies"]:
            if not isinstance(p, dict): continue
            try:
                ptype = str(p.get("type", "")).lower()
                name = str(p.get("name", "node"))
                server, port = str(p.get("server", "")), str(p.get("port", ""))
                if ptype == "ss":
                    auth = base64.urlsafe_b64encode(f"{p.get('cipher', '')}:{p.get('password', '')}".encode()).decode().replace("=", "")
                    uris.append(f"ss://{auth}@{server}:{port}#{name}")
                elif ptype == "trojan":
                    uris.append(f"trojan://{p.get('password', '')}@{server}:{port}?sni={p.get('sni', '')}#{name}")
                elif ptype == "vless":
                    params = {"type": p.get("network", "tcp"), "security": "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")}
                    uris.append(f"vless://{p.get('uuid', '')}@{server}:{port}?{urlencode(params)}#{name}")
                elif ptype == "vmess":
                    vj = {"v":"2", "ps":name, "add":server, "port":port, "id":p.get("uuid", ""), "net":p.get("network", "tcp")}
                    v_str = base64.b64encode(json.dumps(vj).encode()).decode()
                    uris.append(f"vmess://{v_str}")
            except: continue
        return uris
    except: return []

def get_nodes_from_url(url):
    try:
        r = session.get(url, timeout=10)
        content = r.text.strip()
        # 优先解 Base64
        decoded = b64_decode(content)
        if any(p + "://" in decoded.lower() for p in PROTOCOLS): return decoded
        # 其次处理 YAML
        if "proxies" in content: return "\n".join(parse_clash_proxies(content))
        return content
    except Exception as e:
        print(f"❌ 错误: {url} - {e}")
        return ""

def parse_to_uri(node):
    try:
        node = node.strip()
        if not any(node.startswith(p + "://") for p in PROTOCOLS): return None
        return node
    except: return None

def fingerprint(uri):
    return hashlib.md5(uri.encode()).hexdigest()

def extract_nodes():
    if not os.path.exists("valid_subs.txt"): return
    with open("valid_subs.txt", "r") as f: urls = [line.strip() for line in f if line.strip()]
    
    raw_nodes = set()
    with ThreadPoolExecutor(max_workers=10) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                for c in content.splitlines():
                    if any(c.startswith(p + "://") for p in PROTOCOLS): raw_nodes.add(c)
    
    results = [u for u in raw_nodes if parse_to_uri(u)]
    
    with open("all_nodes.txt", "w", encoding="utf-8") as f: f.write("\n".join(results))
    with open("sub_base64.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(results).encode()).decode())
    print(f"✅ 抓取完成，共计 {len(results)} 个节点。")

if __name__ == "__main__":
    extract_nodes()
