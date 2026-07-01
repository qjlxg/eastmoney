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
# 辅助函数定义
# ----------------------------
def b64_decode(data: str) -> str:
    if not data: return ""
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("utf-8", "ignore")
    except Exception:
        return ""

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
                # ... (此处保留你原有的逻辑，为了篇幅略去详细实现)
                # 确保完整性请使用上一条回复中的完整解析逻辑
            except: continue
        return extracted_uris
    except: return []

# --- 此函数必须定义在 extract_nodes 之前 ---
def get_nodes_from_url(url):
    url = url.strip()
    if not url or url.startswith("#"): return ""
    try:
        r = session.get(url, timeout=(5, 15))
        if r.status_code != 200: return ""
        r.encoding = r.apparent_encoding
        content = r.text.strip()
        clean_content = "".join(content.split())
        if re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", clean_content):
            decoded = b64_decode(clean_content)
            if any(p + "://" in decoded.lower() for p in PROTOCOLS): return decoded
        if "proxies" in content:
            clash_uris = parse_clash_proxies(content)
            if clash_uris: return "\n".join(clash_uris)
        return content
    except Exception: return ""

def parse_to_uri(node: str):
    # ... (保持原逻辑)
    return None

def fingerprint(uri):
    # ... (保持原逻辑)
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
        # 现在 get_nodes_from_url 已定义，这里就不会报错了
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
