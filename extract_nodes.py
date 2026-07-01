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
        
        # 只有当内容看起来像 Base64 格式时才尝试解码 (A-Z, a-z, 0-9, +, /, =)
        if re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", content):
            decoded = b64_decode(content)
            if any(p + "://" in decoded.lower() for p in PROTOCOLS):
                return decoded
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

        # --- VMess 特殊处理 (保持所有字段不丢失) ---
        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            if not raw: return None
            j = json.loads(raw)
            # 确保 v 和 ps 基础字段存在
            if "v" not in j: j["v"] = "2"
            if "ps" not in j: j["ps"] = "vmess"
            # 使用 separators 去掉空格, sort_keys 确保 JSON 字符串一致性以便去重
            new_json = json.dumps(j, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
            return "vmess://" + base64.b64encode(new_json.encode()).decode()

        # --- 其他协议通用处理 (VLESS/Trojan/SS/Hy2) ---
        u = urlparse(node)
        
        # 规范化 Query 参数：排序参数键值对，防止因顺序不同导致去重失败
        q = parse_qs(u.query)
        sorted_query = urlencode(sorted(q.items()), doseq=True)
        
        # 提取备注
        name = unquote(u.fragment) if u.fragment else u.scheme
        
        # 重新组合规范化的 URI
        clean_uri = urlunparse((
            u.scheme,
            u.netloc,
            u.path,
            u.params,
            sorted_query,
            name
        ))
        return clean_uri

    except Exception:
        return None

# ----------------------------
# 节点指纹（用于去重）
# ----------------------------
def fingerprint(uri):
    # 以不含备注 (# 后面部分) 的 URI 作为唯一特征进行 MD5
    base_part = uri.split('#')[0]
    return hashlib.md5(base_part.encode()).hexdigest()

# ----------------------------
# 主逻辑
# ----------------------------
def extract_nodes():
    input_file = "valid_subs.txt"
    output_file = "all_nodes.txt"

    if not os.path.exists(input_file):
        print(f"❌ 找不到输入文件: {input_file}")
        return

    urls = [i.strip() for i in open(input_file, encoding="utf-8") if i.strip()]
    print(f"开始处理 {len(urls)} 个订阅源...")

    raw_nodes = set()

    # 并发抓取
    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                # 兼容多种分隔符
                chunks = re.split(r'[\s\n\r]+', content)
                for c in chunks:
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

    # 写入文件
    with open(output_file, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")

    print(f"✅ 完成：已输出 {len(results)} 条节点 -> {output_file}")


if __name__ == "__main__":
    extract_nodes()
