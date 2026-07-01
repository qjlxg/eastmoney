import re, os, requests, base64, json, hashlib, yaml
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 确保工作目录为脚本所在目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5",
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# requests 会话配置
# ----------------------------
session = requests.Session()
retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))
session.headers.update({"User-Agent": "v2rayN/6.23"})

# ----------------------------
# Base64 解码工具
# ----------------------------
def b64_decode(data: str) -> str:
    if not data: return ""
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("utf-8", "ignore")
    except Exception:
        return ""

# ----------------------------
# Clash YAML 转 URI 逻辑 (修复版)
# ----------------------------
def parse_clash_proxies(content):
    try:
        data = yaml.safe_load(content)
        if not data or not isinstance(data, dict) or "proxies" not in data:
            return []

        extracted_uris = []
        for p in data["proxies"]:
            if not isinstance(p, dict): continue
            try:
                ptype = str(p.get("type", "")).lower()
                name = str(p.get("name", "node"))
                server = str(p.get("server", ""))
                port = str(p.get("port", ""))
                if not server or not port: continue

                if ptype == "ss":
                    cipher = p.get("cipher", "")
                    pwd = p.get("password", "")
                    auth = base64.urlsafe_b64encode(f"{cipher}:{pwd}".encode()).decode().replace("=", "")
                    extracted_uris.append(f"ss://{auth}@{server}:{port}#{name}")

                elif ptype == "trojan":
                    pwd = p.get("password", "")
                    sni = p.get("sni", p.get("servername", ""))
                    query = urlencode({"sni": sni}) if sni else ""
                    extracted_uris.append(f"trojan://{pwd}@{server}:{port}?{query}#{name}")

                elif ptype == "vless":
                    uuid = p.get("uuid", "")
                    if not uuid: continue
                    params = {
                        "type": p.get("network", "tcp"),
                        "security": "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none"),
                        "sni": p.get("servername", p.get("sni", "")),
                        "flow": p.get("flow", ""),
                        "fp": p.get("client-fingerprint", ""),
                        "alpn": p.get("alpn", ""),
                        "path": p.get("ws-opts", {}).get("path", p.get("grpc-opts", {}).get("service-name", "")),
                        "host": p.get("ws-opts", {}).get("headers", {}).get("Host", "")
                    }
                    if p.get("reality-opts"):
                        params["pbk"] = p["reality-opts"].get("public-key", "")
                        params["sid"] = p["reality-opts"].get("short-id", "")

                    query = urlencode({k: v for k, v in params.items() if v})
                    extracted_uris.append(f"vless://{uuid}@{server}:{port}?{query}#{name}")

                elif ptype == "vmess":
                    uuid = p.get("uuid", "")
                    if not uuid: continue
                    vj = {
                        "v": "2", "ps": name, "add": server, "port": port,
                        "id": uuid, "aid": p.get("alterId", 0),
                        "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                        "tls": "tls" if p.get("tls") else "",
                        "sni": p.get("servername", p.get("sni", "")),
                        "fp": p.get("client-fingerprint", "")
                    }
                    if vj["net"] == "ws":
                        vj["path"] = p.get("ws-opts", {}).get("path", "")
                        vj["host"] = p.get("ws-opts", {}).get("headers", {}).get("Host", "")
                    elif vj["net"] == "grpc":
                        vj["path"] = p.get("grpc-opts", {}).get("service-name", "")
                    
                    v_str = base64.b64encode(json.dumps(vj, separators=(',', ':')).encode()).decode()
                    extracted_uris.append(f"vmess://{v_str}")
            except (KeyError, Exception):
                continue
        return extracted_uris
    except yaml.YAMLError:
        return []

# ----------------------------
# 格式化与规范化 URI
# ----------------------------
def parse_to_uri(node: str):
    try:
        node = node.strip()
        if not any(node.startswith(p + "://") for p in PROTOCOLS): return None

        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            if not raw: return None
            j = json.loads(raw)
            j.setdefault("v", "2")
            j.setdefault("ps", "vmess")
            if "add" in j: j["add"] = j["add"].lower()
            return "vmess://" + base64.b64encode(json.dumps(j, separators=(',', ':'), sort_keys=True).encode()).decode()

        u = urlparse(node)
        q = parse_qs(u.query, keep_blank_values=True)
        sorted_items = []
        for k in sorted(q.keys()):
            vals = [v.strip().lower() if k.lower() in ["tls", "security", "sni", "fp", "net", "type"] else v.strip() for v in q[k]]
            sorted_items.append((k, sorted(vals)))
        
        return urlunparse((u.scheme, u.netloc.lower(), u.path, u.params, urlencode(sorted_items, doseq=True), u.fragment))
    except (json.JSONDecodeError, Exception):
        return None

# ----------------------------
# 节点指纹 (用于去重)
# ----------------------------
def fingerprint(uri):
    try:
        if uri.startswith("vmess://"):
            j = json.loads(b64_decode(uri[8:]))
            core = {k: str(j.get(k, "")).strip().lower() for k in ["add", "port", "id", "net", "host", "path", "tls", "sni"]}
            return hashlib.md5(json.dumps(core, sort_keys=True).encode()).hexdigest()
        else:
            u = urlparse(uri)
            identity = [u.scheme.lower(), (u.username or "").lower(), (u.hostname or "").lower(), str(u.port or ""), u.path]
            return hashlib.md5(str(identity).encode()).hexdigest()
    except Exception:
        return hashlib.md5(uri.encode()).hexdigest()

# ----------------------------
# 主逻辑
# ----------------------------
def extract_nodes():
    input_file, output_file, b64_output_file = "valid_subs.txt", "all_nodes.txt", "sub_base64.txt"
    if not os.path.exists(input_file): return

    with open(input_file, "r", encoding="utf-8") as f:
        urls = [i.strip() for i in f if i.strip()]

    raw_nodes = set()
    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                for c in re.split(r'[\s\n\r]+', content):
                    if any(c.startswith(p + "://") for p in PROTOCOLS):
                        raw_nodes.add(c)

    results, seen_fps = [], set()
    for n in raw_nodes:
        uri = parse_to_uri(n)
        if not uri: continue
        fp = fingerprint(uri)
        if fp not in seen_fps:
            seen_fps.add(fp)
            results.append(uri)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(results))
    with open(b64_output_file, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(results).encode()).decode())
    print(f"✅ 处理完成，共 {len(results)} 个去重节点。")

if __name__ == "__main__":
    extract_nodes()
