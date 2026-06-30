import re, os, requests, base64, yaml, json, socket, hashlib, sys
from urllib.parse import urlparse, unquote, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PROTOCOLS = [
    "vmess", "trojan", "http", "ss", "socks5",
    "vless", "hy2", "hysteria2", "anytls", "hysteria", "tuic"
]

# ----------------------------
# session
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
# parse node
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
                "tls": j.get("tls") == "tls",
                "udp": True
            }

        u = urlparse(node)
        proto = u.scheme.lower()
        if proto not in PROTOCOLS:
            return None

        query = parse_qs(u.query)
        params = {k: v[0] for k, v in query.items()}

        stable_hash = hashlib.sha256(node.encode()).hexdigest()[:6]
        name = unquote(u.fragment) if u.fragment else f"{proto}_{stable_hash}"

        res = {
            "name": name,
            "type": proto,
            "server": u.hostname,
            "port": int(u.port) if u.port else 443,
        }

        # ---------------- ss ----------------
        if proto == "ss":
            if "@" in u.netloc:
                res["cipher"], res["password"] = u.username, u.password
            else:
                decoded = b64_decode(u.username)
                if ":" in decoded:
                    cipher, password = decoded.split(":", 1)
                    res["cipher"], res["password"] = cipher, password
                else:
                    return None

        # ---------------- vless ----------------
        elif proto == "vless":
            res["uuid"] = u.username
            res["udp"] = True
            if params.get("security") in ["tls", "reality"]:
                res["tls"] = True
                res["sni"] = params.get("sni", u.hostname)
                if params.get("flow"):
                    res["flow"] = params["flow"]
                if params.get("security") == "reality":
                    res["reality-opts"] = {
                        "public-key": params.get("pbk", ""),
                        "short-id": params.get("sid", ""),
                        "fingerprint": params.get("fp", "chrome")
                    }

        # ---------------- trojan ----------------
        elif proto == "trojan":
            res["password"] = u.username
            res["tls"] = True
            res["sni"] = params.get("sni", u.hostname)

        # ---------------- hysteria2 ----------------
        elif proto in ["hysteria2", "hy2"]:
            res["type"] = "hysteria2"
            res["password"] = u.username

        return res
    except:
        return None

# ----------------------------
# fingerprint
# ----------------------------
def get_node_fingerprint(p):
    core = {
        "t": p.get("type"),
        "s": str(p.get("server", "")).lower().strip(),
        "p": p.get("port"),
        "cred": p.get("uuid") or p.get("password") or p.get("username", "")
    }
    return hashlib.md5(json.dumps(core, sort_keys=True).encode()).hexdigest()

# ----------------------------
# build URI (关键：明文输出)
# ----------------------------
def build_uri(p):
    proto = p.get("type")

    if proto == "vmess":
        cfg = {
            "v": "2",
            "ps": p.get("name"),
            "add": p.get("server"),
            "port": str(p.get("port")),
            "id": p.get("uuid"),
            "aid": str(p.get("alterId", 0)),
            "net": "tcp",
            "tls": "tls" if p.get("tls") else ""
        }
        return "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()

    if proto == "vless":
        uri = f"vless://{p.get('uuid')}@{p.get('server')}:{p.get('port')}"
        q = []
        if p.get("tls"):
            q.append("security=tls")
        if p.get("sni"):
            q.append(f"sni={p['sni']}")
        if p.get("flow"):
            q.append(f"flow={p['flow']}")
        if p.get("reality-opts"):
            ro = p["reality-opts"]
            q += [
                "security=reality",
                f"pbk={ro.get('public-key','')}",
                f"sid={ro.get('short-id','')}",
                f"fp={ro.get('fingerprint','chrome')}"
            ]
        if q:
            uri += "?" + "&".join(q)
        return uri + f"#{quote(p.get('name','vless'))}"

    if proto == "trojan":
        uri = f"trojan://{p.get('password')}@{p.get('server')}:{p.get('port')}"
        if p.get("sni"):
            uri += f"?sni={p['sni']}"
        return uri + f"#{quote(p.get('name','trojan'))}"

    if proto == "ss":
        raw = f"{p['cipher']}:{p['password']}"
        enc = base64.b64encode(raw.encode()).decode()
        return f"ss://{enc}@{p['server']}:{p['port']}#{quote(p.get('name','ss'))}"

    if proto in ["hysteria2", "hy2"]:
        return f"hysteria2://{p.get('password')}@{p.get('server')}:{p.get('port')}#{quote(p.get('name','hy2'))}"

    return None

# ----------------------------
# Clash YAML
# ----------------------------
def to_clash(p):
    t = p["type"]
    base = {
        "name": p["name"],
        "server": p["server"],
        "port": p["port"],
    }

    if t == "vless":
        base.update({
            "type": "vless",
            "uuid": p["uuid"],
            "tls": p.get("tls", False)
        })
    elif t == "trojan":
        base.update({
            "type": "trojan",
            "password": p["password"],
            "tls": True
        })
    elif t == "ss":
        base.update({
            "type": "ss",
            "cipher": p["cipher"],
            "password": p["password"]
        })
    else:
        base["type"] = t

    return base

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
                raw_nodes.update(c for c in chunks if any(p + "://" in c.lower() for p in PROTOCOLS))

    proxies = []
    seen = set()

    for n in raw_nodes:
        p = parse_node(n)
        if not p or not p.get("server"):
            continue

        fp = get_node_fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        proxies.append(p)

    # ---------------- 写 all_nodes ----------------
    with open("all_nodes.txt", "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    # ---------------- 明文订阅 ----------------
    with open("sub.txt", "w", encoding="utf-8") as f:
        for p in proxies:
            uri = build_uri(p)
            if uri:
                f.write(uri + "\n")

    # ---------------- base64订阅 ----------------
    sub_b64 = base64.b64encode("\n".join(open("sub.txt", encoding="utf-8")).encode()).decode()
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(sub_b64)

    # ---------------- Clash YAML ----------------
    clash = {"proxies": [to_clash(p) for p in proxies]}
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash, f, allow_unicode=True)

    print(f"✅ 完成：节点 {len(proxies)} 个")
    print("📄 sub.txt / sub_base64.txt / config.yaml 已生成")

if __name__ == "__main__":
    extract_nodes()