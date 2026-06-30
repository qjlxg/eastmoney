import re, os, requests, base64, json, hashlib
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5",
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# requests session
# ----------------------------
session = requests.Session()
retry = Retry(total=2, backoff_factor=0.3,
              status_forcelist=[500, 502, 503, 504])
session.mount("http://", HTTPAdapter(max_retries=retry))
session.mount("https://", HTTPAdapter(max_retries=retry))


# ----------------------------
# base64 decode
# ----------------------------
def b64_decode(data: str) -> str:
    data = data.strip().replace('-', '+').replace('_', '/')
    data += "=" * (-len(data) % 4)
    for func in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return func(data).decode("utf-8", "ignore")
        except:
            continue
    return ""


# ----------------------------
# fetch subscription
# ----------------------------
def get_nodes_from_url(url):
    try:
        r = session.get(url.strip(), timeout=(5, 10))
        if r.status_code != 200:
            return ""
        content = r.text.strip()
        decoded = b64_decode(content)
        return decoded if any(p + "://" in decoded.lower() for p in PROTOCOLS) else content
    except:
        return ""


# ----------------------------
# parse node -> return URI
# ----------------------------
def parse_to_uri(node: str):
    try:
        if not any(p + "://" in node for p in PROTOCOLS):
            return None

        # vmess
        if node.startswith("vmess://"):
            raw = b64_decode(node[8:])
            j = json.loads(raw)

            cfg = {
                "v": "2",
                "ps": j.get("ps", "vmess"),
                "add": j.get("add"),
                "port": str(j.get("port")),
                "id": j.get("id"),
                "aid": str(j.get("aid", 0)),
                "net": "tcp",
                "tls": "tls" if j.get("tls") == "tls" else ""
            }
            return "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()

        u = urlparse(node)
        proto = u.scheme.lower()
        q = parse_qs(u.query)

        name = unquote(u.fragment) if u.fragment else proto

        # vless
        if proto == "vless":
            uri = f"vless://{u.username}@{u.hostname}:{u.port or 443}"
            params = []
            if q.get("security"):
                params.append(f"security={q['security'][0]}")
            if q.get("sni"):
                params.append(f"sni={q['sni'][0]}")
            if q.get("flow"):
                params.append(f"flow={q['flow'][0]}")
            if params:
                uri += "?" + "&".join(params)
            return uri + f"#{name}"

        # trojan
        if proto == "trojan":
            uri = f"trojan://{u.username}@{u.hostname}:{u.port or 443}"
            if "sni" in q:
                uri += f"?sni={q['sni'][0]}"
            return uri + f"#{name}"

        # ss
        if proto == "ss":
            if "@" in u.netloc:
                cipher, password = u.username, u.password
            else:
                decoded = b64_decode(u.username)
                if ":" in decoded:
                    cipher, password = decoded.split(":", 1)
                else:
                    return None

            raw = f"{cipher}:{password}"
            enc = base64.b64encode(raw.encode()).decode()
            return f"ss://{enc}@{u.hostname}:{u.port}#{name}"

        # hysteria2
        if proto in ["hysteria2", "hy2"]:
            return f"hysteria2://{u.username}@{u.hostname}:{u.port}#{name}"

        # fallback
        return node.strip()

    except:
        return None


# ----------------------------
# fingerprint dedup
# ----------------------------
def fingerprint(uri):
    return hashlib.md5(uri.encode()).hexdigest()


# ----------------------------
# main
# ----------------------------
def extract_nodes():
    if not os.path.exists("valid_subs.txt"):
        return

    urls = [i.strip() for i in open("valid_subs.txt", encoding="utf-8") if i.strip()]

    raw_nodes = set()

    with ThreadPoolExecutor(max_workers=25) as ex:
        for content in ex.map(get_nodes_from_url, urls):
            if content:
                chunks = re.split(r'[\s\n\r]+', content)
                raw_nodes.update(c for c in chunks if any(p + "://" in c for p in PROTOCOLS))

    results = []
    seen = set()

    for n in raw_nodes:
        uri = parse_to_uri(n)
        if not uri:
            continue

        fp = fingerprint(uri)
        if fp in seen:
            continue

        seen.add(fp)
        results.append(uri)

    # ----------------------------
    # ONLY OUTPUT FILE
    # ----------------------------
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")

    print(f"✅ 完成：已输出 {len(results)} 条节点 -> all_nodes.txt")


if __name__ == "__main__":
    extract_nodes()