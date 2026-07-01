import re, os, requests, base64, json, hashlib
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
# 获取订阅内容
# ----------------------------
def get_nodes_from_url(url):
    url = url.strip()
    if not url or url.startswith("#"): return ""
    try:
        r = session.get(url, timeout=(5, 15))
        if r.status_code != 200:
            return ""
        content = r.text.strip()
        
        if re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", content):
            decoded = b64_decode(content)
            if any(p + "://" in decoded.lower() for p in PROTOCOLS):
                return decoded
        return content
    except Exception:
        return ""

# ----------------------------
# 格式化与规范化 URI (用于最终输出)
# ----------------------------
def parse_to_uri(node: str):
    try:
        node = node.strip()
        if not any(node.startswith(p + "://") for p in PROTOCOLS):
            return None

        # --- VMess 特殊处理 ---
        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            if not raw: return None
            j = json.loads(raw)
            # 基础字段规范化
            if "v" not in j: j["v"] = "2"
            if "ps" not in j: j["ps"] = "vmess"
            # 核心地址强制小写
            if "add" in j: j["add"] = j["add"].lower()
            
            new_json = json.dumps(j, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
            return "vmess://" + base64.b64encode(new_json.encode()).decode()

        # --- 其他协议通用处理 ---
        u = urlparse(node)
        q = parse_qs(u.query)
        
        # 1. 规范化主机名 (转小写)
        netloc = u.netloc
        if u.hostname:
            netloc = netloc.replace(u.hostname, u.hostname.lower())
            
        # 2. 规范化 Query 参数键值对
        sorted_items = []
        for k in sorted(q.keys()):
            sorted_items.append((k, sorted(q[k])))
        sorted_query = urlencode(sorted_items, doseq=True)
        
        # 3. 保持原始备注 (fragment) 
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
# 节点指纹（极高精度去重）
# ----------------------------
def fingerprint(uri):
    """
    提取协议身份核心特征，对齐布尔值、大小写，排除无关字段
    """
    try:
        if uri.startswith("vmess://"):
            raw = b64_decode(uri[8:])
            if not raw: return hashlib.md5(uri.encode()).hexdigest()
            j = json.loads(raw)
            # VMess 身份核心字段 (移除了 aid, 增加了 serviceName/alpn/fp)
            core = {
                "add": str(j.get("add", "")).strip().lower(),
                "port": str(j.get("port", "")).strip(),
                "id": str(j.get("id", "")).strip().lower(),
                "net": str(j.get("net", "tcp")).strip().lower(),
                "type": str(j.get("type", "none")).strip().lower(),
                "host": str(j.get("host", "")).strip().lower(),
                "path": str(j.get("path", "")).strip().lower(),
                "tls": str(j.get("tls", "none")).strip().lower(),
                "sni": str(j.get("sni", "")).strip().lower(),
                "serviceName": str(j.get("serviceName", "")).strip().lower(),
                "alpn": str(j.get("alpn", "")).strip().lower(),
                "fp": str(j.get("fp", "")).strip().lower(),
            }
            return hashlib.md5(json.dumps(core, sort_keys=True).encode()).hexdigest()

        else:
            u = urlparse(uri)
            # 拆解身份信息，确保 hostname、username 规范化，不含 fragment (备注)
            identity = [
                u.scheme.lower(),
                (u.username or "").lower(),
                (u.password or ""),
                (u.hostname or "").lower(),
                str(u.port or ""),
                u.path
            ]
            
            q = parse_qs(u.query)
            relevant_params = []
            IGNORE_KEYS = {"ps", "name", "remark", "sub", "t"}
            
            for k in sorted(q.keys()):
                k_lower = k.lower()
                if k_lower in IGNORE_KEYS:
                    continue
                
                vals = q[k]
                normalized_vals = []
                for v in vals:
                    v_clean = v.strip().lower()
                    # 布尔值对齐：1/true -> true, 0/false -> false
                    if v_clean in ("1", "true"):
                        normalized_vals.append("true")
                    elif v_clean in ("0", "false"):
                        normalized_vals.append("false")
                    else:
                        # 对于 sni, host 等连接字段强制小写，其余保持原样(但去空格)
                        if k_lower in ("sni", "host", "security", "type", "net", "mode"):
                            normalized_vals.append(v_clean)
                        else:
                            normalized_vals.append(v.strip())
                
                relevant_params.append((k_lower, sorted(normalized_vals)))
            
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

    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                chunks = re.split(r'[\s\n\r]+', content)
                for c in chunks:
                    c = c.strip()
                    if any(c.startswith(p + "://") for p in PROTOCOLS):
                        raw_nodes.add(c)

    results = []
    seen_fps = set()

    for n in raw_nodes:
        uri = parse_to_uri(n)
        if not uri:
            continue

        fp = fingerprint(uri)
        if fp in seen_fps:
            continue

        seen_fps.add(fp)
        results.append(uri)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(r + "\n")
        print(f"✅ 完成：已去重并输出 {len(results)} 条节点 -> {output_file}")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")


if __name__ == "__main__":
    extract_nodes()
