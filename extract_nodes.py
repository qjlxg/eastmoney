import re, os, requests, base64, json, hashlib, csv, socket
import geoip2.database
from urllib.parse import urlparse, unquote, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 设置工作目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 仅保留指定的协议
PROTOCOLS = ["hy2", "hysteria2", "anytls", "hysteria", "tuic"]

# ----------------------------
# GeoIP & DNS 增强
# ----------------------------
GEO_DB_PATH = "GeoLite2-Country.mmdb"
geo_reader = geoip2.database.Reader(GEO_DB_PATH) if os.path.exists(GEO_DB_PATH) else None
dns_cache = {}
geo_cache = {}

def get_ip_from_host(host):
    if host in dns_cache: return dns_cache[host]
    try:
        # 如果本身就是IP则直接返回
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return host
        ip = socket.gethostbyname(host)
        dns_cache[host] = ip
        return ip
    except:
        return None

def get_country_info(host):
    if host in geo_cache: return geo_cache[host]

    ip = get_ip_from_host(host)
    if not ip or not geo_reader:
        return None

    try:
        response = geo_reader.country(ip)
        country = response.country.names.get('zh-CN', response.country.name)
        if country:
            geo_cache[host] = country
            return country
        return None
    except:
        return None

# ----------------------------
# 增强型 Base64 解码
# ----------------------------
def b64_decode(data: str) -> str:
    if not data: return ""
    data = data.strip().replace('-', '+').replace('_', '/')
    # 补齐长度
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode("utf-8", "ignore")
    except:
        return ""

# ----------------------------
# 网络请求设置
# ----------------------------
session = requests.Session()
session.headers.update({
    "User-Agent": "v2rayN/6.23", # 模拟常用客户端UA
})
retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))

def get_nodes_from_url(url):
    try:
        r = session.get(url.strip(), timeout=(5, 15))
        if r.status_code != 200: return url, ""
        content = r.text.strip()

        # 尝试解码订阅内容
        decoded = b64_decode(content)
        # 如果解码后包含已知协议，说明是Base64订阅
        if any(p + "://" in decoded.lower() for p in PROTOCOLS):
            return url, decoded
        return url, content
    except Exception as e:
        return url, ""

# ----------------------------
# 节点解析与标准化
# ----------------------------
def parse_to_uri(node: str):
    try:
        node = node.strip()
        if not node or "://" not in node: return None

        # 获取原始备注 (fragment)
        if '#' in node:
            parts = node.split('#', 1)
            clean_node = parts[0]
            original_tag = unquote(parts[1])
        else:
            clean_node = node
            original_tag = "Node"

        u = urlparse(clean_node)
        hostname = u.hostname

        if not hostname:
            return node

        # 获取地理位置，如果识别到则添加前缀，否则保持原样
        country = get_country_info(hostname)
        if country:
            new_tag = f"{country}-{original_tag}"
        else:
            new_tag = original_tag

        # 重新组合 URI
        new_uri = urlunparse((
            u.scheme, u.netloc, u.path, u.params, u.query, new_tag
        ))
        return new_uri

    except Exception:
        return node

# ----------------------------
# 主程序
# ----------------------------
def extract_nodes():
    input_file = "valid_subs.txt"
    if not os.path.exists(input_file):
        print(f"❌ 未找到 {input_file}")
        return

    exclude_domains = ["githubusercontent.com", "s3.v2rayse.com"]
    all_urls = [i.strip() for i in open(input_file, encoding="utf-8") if i.strip() and not i.startswith("#")]
    urls = [url for url in all_urls if not any(d in url for d in exclude_domains)]

    print(f"🚀 开始抓取 {len(urls)} 个订阅源...")

    raw_nodes = set()
    stats = []

    # 并发抓取
    with ThreadPoolExecutor(max_workers=20) as ex:
        for url, content in ex.map(get_nodes_from_url, urls):
            if content:
                # 仅筛选我们定义的 PROTOCOLS
                pattern = r'(?:' + '|'.join(PROTOCOLS) + r')://[^\s]+'
                nodes_in_sub = re.findall(pattern, content, re.IGNORECASE)
                raw_nodes.update(nodes_in_sub)
                stats.append({"url": url, "count": len(nodes_in_sub)})
                print(f"✅ 抓取成功: {url[:40]}... (找到 {len(nodes_in_sub)} 节点)")
            else:
                stats.append({"url": url, "count": 0})

    # 保存统计
    stats.sort(key=lambda x: x["count"], reverse=True)
    with open("sub_stats.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "count"])
        writer.writeheader()
        writer.writerows(stats)

    # 解析、去重、命名
    print(f"🔄 正在处理 {len(raw_nodes)} 个原始节点...")
    final_nodes = []
    seen_fingerprints = set()

    for n in raw_nodes:
        processed_uri = parse_to_uri(n)
        if not processed_uri: continue

        # 提取核心部分作为指纹（去除备注部分进行去重）
        fingerprint = hashlib.md5(processed_uri.split('#')[0].encode()).hexdigest()

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            final_nodes.append(processed_uri)

    # 写入结果
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for node in final_nodes:
            f.write(node + "\n")

    # 生成订阅格式 (Base64)
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        b64_content = base64.b64encode("\n".join(final_nodes).encode()).decode()
        f.write(b64_content)

    print("-" * 30)
    print(f"⭐ 处理完成!")
    print(f"📝 有效唯一节点: {len(final_nodes)}")
    print(f"输出文件: all_nodes.txt (明文), sub_base64.txt (订阅格式)")

if __name__ == "__main__":
    extract_nodes()
