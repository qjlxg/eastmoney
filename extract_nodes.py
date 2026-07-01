import re, os, requests, base64, json, hashlib, yaml
from urllib.parse import urlparse, unquote, parse_qs, urlencode, urlunparse
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
session.headers.update({
    "User-Agent": "v2rayN/6.23", 
})

# ----------------------------
# Base64 解码工具
# ----------------------------
def b64_decode(data: str) -> str:
    if not data: return ""
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("utf-8", "ignore")
    except:
        return ""

# ----------------------------
# Clash YAML 转 URI 逻辑
# ----------------------------
def parse_clash_proxies(content):
    """
    从 Clash YAML 中提取节点。修复了 HTTP 拼接错误并完善了 gRPC/Reality 字段映射。
    """
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
                
                if ptype == "ss":
                    cipher = p.get("cipher", "")
                    pwd = p.get("password", "")
                    # 采用 urlsafe 编码更符合 SS 链接规范
                    auth = base64.urlsafe_b64encode(f"{cipher}:{pwd}".encode()).decode().replace("=", "")
                    extracted_uris.append(f"ss://{auth}@{server}:{port}#{name}")

                elif ptype == "trojan":
                    pwd = p.get("password", "")
                    sni = p.get("sni", p.get("servername", ""))
                    query = urlencode({"sni": sni}) if sni else ""
                    extracted_uris.append(f"trojan://{pwd}@{server}:{port}?{query}#{name}")

                elif ptype == "vless":
                    uuid = p.get("uuid", "")
                    params = {
                        "type": p.get("network", "tcp"),
                        "security": "tls" if p.get("tls") else "none",
                        "sni": p.get("servername", p.get("sni", "")),
                        "flow": p.get("flow", ""),
                        "fp": p.get("client-fingerprint", ""),
                        "alpn": p.get("alpn", ""),
                        "path": p.get("ws-opts", {}).get("path", p.get("grpc-opts", {}).get("service-name", "")),
                        "host": p.get("ws-opts", {}).get("headers", {}).get("Host", "")
                    }
                    if p.get("reality-opts"):
                        params["security"] = "reality"
                        params["pbk"] = p["reality-opts"].get("public-key", "")
                        params["sid"] = p["reality-opts"].get("short-id", "")
                    
                    query = urlencode({k: v for k, v in params.items() if v})
                    extracted_uris.append(f"vless://{uuid}@{server}:{port}?{query}#{name}")

                elif ptype == "vmess":
                    vj = {
                        "v": "2", "ps": name, "add": server, "port": port,
                        "id": p.get("uuid", ""), "aid": p.get("alterId", 0),
                        "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                        "tls": "tls" if p.get("tls") else "",
                        "sni": p.get("servername", p.get("sni", "")),
                        "alpn": p.get("alpn", ""), "fp": p.get("client-fingerprint", "")
                    }
                    if vj["net"] == "ws" and p.get("ws-opts"):
                        vj["path"] = p["ws-opts"].get("path", "")
                        vj["host"] = p["ws-opts"].get("headers", {}).get("Host", "")
                    elif vj["net"] == "grpc" and p.get("grpc-opts"):
                        vpath = p["grpc-opts"].get("service-name", "")
                        vj["path"] = vpath
                        vj["serviceName"] = vpath # 增强 gRPC 兼容性
                    
                    v_str = base64.b64encode(json.dumps(vj, separators=(',', ':')).encode()).decode()
                    extracted_uris.append(f"vmess://{v_str}")

                elif ptype == "http":
                    user = p.get("username", "")
                    pwd = p.get("password", "")
                    # 修正：auth 已经带了 @，后面不需要再重复 @
                    auth = f"{user}:{pwd}@" if user else ""
                    tls = "true" if p.get("tls") else "false"
                    extracted_uris.append(f"http://{auth}{server}:{port}?tls={tls}#{name}")

            except:
                continue
        return extracted_uris
    except:
        return []

# ----------------------------
# 获取订阅内容
# ----------------------------
def get_nodes_from_url(url):
    url = url.strip()
    if not url or url.startswith("#"): return ""
    try:
        r = session.get(url, timeout=(5, 15))
        if r.status_code != 200:
            return ""
        # 核心：自动识别编码，防止备注乱码
        r.encoding = r.apparent_encoding
        content = r.text.strip()
        
        # 1. 尝试识别并解码 Base64 (增强版判定：允许内容包含空行)
        clean_content = "".join(content.split())
        if re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", clean_content):
            decoded = b64_decode(clean_content)
            if any(p + "://" in decoded.lower() for p in PROTOCOLS):
                return decoded
        
        # 2. 尝试 Clash YAML 解析
        if "proxies" in content:
            clash_uris = parse_clash_proxies(content)
            if clash_uris:
                return "\n".join(clash_uris)
                
        return content
    except Exception:
        return ""

# ----------------------------
# 格式化与规范化 URI
# ----------------------------
def parse_to_uri(node: str):
    try:
        node = node.strip()
        if not any(node.startswith(p + "://") for p in PROTOCOLS):
            return None

        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            if not raw: return None
            j = json.loads(raw)
            if "v" not in j: j["v"] = "2"
            if "ps" not in j: j["ps"] = "vmess"
            if "add" in j: j["add"] = j["add"].lower()
            new_json = json.dumps(j, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
            return "vmess://" + base64.b64encode(new_json.encode()).decode()

        u = urlparse(node)
        q = parse_qs(u.query, keep_blank_values=True)
        
        netloc = u.netloc
        if u.hostname:
            netloc = netloc.replace(u.hostname, u.hostname.lower())
            
        sorted_items = []
        for k in sorted(q.keys()):
            # 核心：对连接类参数进行小写对齐，大幅提高去重率
            vals = [v.strip().lower() if k.lower() in ["tls", "security", "sni", "fp", "net", "type"] else v.strip() for v in q[k]]
            sorted_items.append((k, sorted(vals)))
        sorted_query = urlencode(sorted_items, doseq=True)
        
        clean_uri = urlunparse((
            u.scheme,
            netloc,
            u.path,
            u.params,
            sorted_query,
            u.fragment
        ))
        return clean_uri
    except Exception:
        return None

# ----------------------------
# 节点指纹 (用于去重)
# ----------------------------
def fingerprint(uri):
    try:
        if uri.startswith("vmess://"):
            raw = b64_decode(uri[8:])
            if not raw: return hashlib.md5(uri.encode()).hexdigest()
            j = json.loads(raw)
            core = {
                "add": str(j.get("add", "")).strip().lower(),
                "port": str(j.get("port", "")).strip(),
                "id": str(j.get("id", "")).strip().lower(),
                "net": str(j.get("net", "tcp")).strip().lower(),
                "host": str(j.get("host", "")).strip().lower(),
                "path": str(j.get("path", "")).strip().lower(),
                "tls": str(j.get("tls", "")).strip().lower(),
                "sni": str(j.get("sni", "")).strip().lower()
            }
            return hashlib.md5(json.dumps(core, sort_keys=True).encode()).hexdigest()
        else:
            u = urlparse(uri)
            # 基础特征：协议 + 用户 + 地址 + 端口 + 路径
            identity = [u.scheme.lower(), (u.username or "").lower(), (u.password or ""), (u.hostname or "").lower(), str(u.port or ""), u.path]
            q = parse_qs(u.query)
            relevant_params = []
            IGNORE_KEYS = {"ps", "name", "remark", "sub", "t"}
            for k in sorted(q.keys()):
                k_lower = k.lower()
                if k_lower in IGNORE_KEYS: continue
                # 对关键参数进行布尔对齐
                vals = []
                for v in q[k]:
                    v_c = v.strip().lower()
                    if v_c in ["1", "true"]: v_c = "true"
                    elif v_c in ["0", "false"]: v_c = "false"
                    vals.append(v_c)
                relevant_params.append((k_lower, sorted(vals)))
            identity.append(tuple(relevant_params))
            return hashlib.md5(str(identity).encode()).hexdigest()
    except Exception:
        return hashlib.md5(uri.split('#')[0].encode()).hexdigest()

# ----------------------------
# 主逻辑
# ----------------------------
def extract_nodes():
    input_file = "valid_subs.txt"
    output_file = "all_nodes.txt"

    if not os.path.exists(input_file):
        print(f"❌ 找不到输入文件: {input_file}")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            urls = [i.strip() for i in f if i.strip()]
    except Exception as e:
        print(f"❌ 读取输入文件失败: {e}")
        return

    print(f"开始处理 {len(urls)} 个订阅源...")
    raw_nodes = set()

    # 使用 ThreadPoolExecutor 并发处理抓取
    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                # 统一分割处理
                chunks = re.split(r'[\s\n\r]+', content)
                for c in chunks:
                    c = c.strip()
                    if any(c.startswith(p + "://") for p in PROTOCOLS):
                        raw_nodes.add(c)

    results = []
    seen_fps = set()

    for n in raw_nodes:
        uri = parse_to_uri(n)
        if not uri: continue
        fp = fingerprint(uri)
        if fp in seen_fps: continue
        seen_fps.add(fp)
        results.append(uri)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(r + "\n")
        print(f"✅ 完成：已输出 {len(results)} 条节点 -> {output_file}")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")

if __name__ == "__main__":
    extract_nodes()
