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
# 增强去重指纹计算
# ----------------------------
def get_node_fingerprint(p):
    """根据核心连接参数生成唯一指纹，解决同一节点不同名称的问题"""
    try:
        # 核心参数：协议、服务器(小写)、端口、关键凭据
        core_parts = {
            "t": p.get("type"),
            "s": str(p.get("server", "")).lower().strip(),
            "p": p.get("port"),
            "cred": p.get("uuid") or p.get("password") or p.get("username", "")
        }
        # 将参数排序并序列化为JSON，再生成MD5
        return hashlib.md5(json.dumps(core_parts, sort_keys=True).encode()).hexdigest()
    except:
        return hashlib.md5(str(p).encode()).hexdigest()

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
                # 兼容多种分割符并过滤空字符
                chunks = re.split(r'[\s\n\r]+', content)
                raw_nodes.update(c for c in chunks if any(p + "://" in c.lower() for p in PROTOCOLS))

    proxies, seen_names, seen_fingerprints = [], set(), set()

    # 第一阶段：解析并初步去重本次抓取的节点
    for n in raw_nodes:
        p = parse_node(n)
        if not p or not p.get("server"): continue
        
        # 计算核心业务指纹
        fp = get_node_fingerprint(p)
        if fp in seen_fingerprints: continue
            
        # 防止名称冲突：如果名称已存在但指纹不同，重命名
        if p["name"] in seen_names:
            p["name"] = f"{p['name']}_{fp[:4]}"
            
        seen_names.add(p["name"])
        seen_fingerprints.add(fp)
        p["fingerprint"] = fp # 暂存指纹用于后续全库比对
        proxies.append(p)

    if not proxies or not os.path.exists("rules.yaml"): return

    with open("rules.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # 第二阶段：全库去重合并
    # 建立现有节点的指纹库
    existing_proxies = config.get("proxies", [])
    merged_proxies_map = {} # fingerprint -> proxy_dict

    # 先处理原配置文件中的节点
    for ep in existing_proxies:
        efp = get_node_fingerprint(ep)
        if efp not in merged_proxies_map:
            merged_proxies_map[efp] = ep

    # 再合并新抓取的节点（如果指纹已存在则忽略）
    for np in proxies:
        nfp = np.pop("fingerprint", None) or get_node_fingerprint(np)
        if nfp not in merged_proxies_map:
            # 确保名称不与已有节点名称冲突
            existing_names = {item["name"] for item in merged_proxies_map.values()}
            base_name = np["name"]
            counter = 1
            while np["name"] in existing_names:
                np["name"] = f"{base_name}_{counter}"
                counter += 1
            merged_proxies_map[nfp] = np

    # 更新到配置
    config["proxies"] = list(merged_proxies_map.values())

    # 提取所有节点名称用于策略组
    all_proxy_names = [p["name"] for p in config["proxies"]]
    for group in config.get("proxy-groups", []):
        if group.get("
