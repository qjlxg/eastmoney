import requests
import re
import os
import base64
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# 配置
# =========================
CHANNELS_FILE = "channels.txt"
BASE_PREFIX = "https://t.me/s/" # 自动补全前缀
MAX_PAGES_PER_CHANNEL = 3     # 每个频道向后翻页的数量

# 订阅特征关键字 (URL 包含以下任意词汇将被优先视为订阅链接)
SUBSCRIPTION_KEYWORDS = [
    'sub', 'subscribe', 'token', 'clash', 'v2ray', 'singbox', 
    'base64', 'raw', 'link', 'config', 'proxypool', 'node', 
    'api/v1', 'yaml', 'yml', 'json', 'txt'
]

# 屏蔽非订阅类域名 (包含 AI、社交、音乐、伊朗本地服务等)
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 'youtu.be','chibaba.ggff.net','Amirinventor2010.bio.link','apkdl.net','paste.gg',
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com','githubusercontent','raw.githubusercontent.com',
    'www.xrayvip.com', 'link.onesy.link', 'wikipedia.org', 'reddit.com',
    'apple.com', 'microsoft.com', 'purl.org', 'w3.org', 'x.com',
    'chatgpt.com', 'claude.ai', 'deepseek.com', 'openai.com', 'perplexity.ai',
    'speedtest.net', 'fast.com', 'spotify.com', 'soundcloud.com',
    'aparat.com', 'rubika.ir', 'uupload.ir', 'uploadboy.com', 'uplod.ir',
    'post.ir', 'cafebazaar.ir', 'snapp.ir', 'arvancloud.ir', 'bertina.ir',
    'radiojavan.com', 'mega.nz', 'f-droid.org', 'visualstudio.com', 'nextjs.org',
    'kubernetes.io', 'helm.sh', 'cloudflarestatus.com', 'reuters.com'
]

# 屏蔽常见静态资源后缀 (注意：.yaml 和 .yml 已从中移除)
BLACKLIST_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
    '.mp4', '.mp3', '.m4a', '.pdf', '.exe', '.dmg', '.apk', 
    '.zip', '.rar', '.7z', '.sh'
]

# 屏蔽保留/虚假 IP 
BLACKLIST_IPS = ['0.0.0.0', '1.0.0.0', '127.0.0.1', '8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4']

session = requests.Session()
# 增加重试机制：处理 429 (频率限制) 和 5xx 错误
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
})

def b64_decode(data):
    """尝试解码 Base64 字符串"""
    try:
        # 补全等号
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        decoded = base64.b64decode(data).decode('utf-8', 'ignore')
        if decoded.startswith('http'):
            return decoded
    except:
        pass
    return None

def extract_links_from_html(html):
    """多维度提取逻辑：HTML属性 + 正文正则 + Base64识别"""
    soup = BeautifulSoup(html, "html.parser")
    found_raw_urls = []

    # 1. 提取所有 <a> 标签的超链接
    for a in soup.find_all('a', href=True):
        found_raw_urls.append(a['href'])

    # 2. 提取文本中所有的裸链接
    text = soup.get_text()
    raw_text_urls = re.findall(r'https?://[^\s<>"\']+', text)
    found_raw_urls.extend(raw_text_urls)

    # 3. 提取可能的 Base64 编码链接
    b64_blocks = re.findall(r'[a-zA-Z0-9+/=]{20,}', text)
    for block in b64_blocks:
        if block.startswith("aHR0"): # 快速过滤
            decoded = b64_decode(block)
            if decoded:
                found_raw_urls.append(decoded)

    clean_subs = []
    for u in found_raw_urls:
        # 增强清理：递归清理末尾干扰字符及非 ASCII 文本（如波斯语后缀）
        u = re.split(r'[^\x00-\x7F]+', u)[0]
        u = u.strip().rstrip(').,;!]>》】"\'#')
        
        try:
            parsed = urlparse(u)
            if not parsed.scheme or not parsed.netloc:
                continue
            
            # 过滤非 http/https 协议
            if parsed.scheme not in ['http', 'https']:
                continue

            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            u_lower = u.lower()

            # 1. 域名黑名单过滤
            if any(domain == blk or domain.endswith("." + blk) for blk in BLACKLIST_DOMAINS):
                continue
            
            # 2. IP 黑名单过滤
            if domain in BLACKLIST_IPS:
                continue

            # 3. 后缀名黑名单过滤
            if any(path.endswith(ext) for ext in BLACKLIST_EXTENSIONS):
                continue

            # 4. 订阅特征关键字正向过滤 (过滤掉不包含特征词的杂乱链接)
            if not any(kw in u_lower for kw in SUBSCRIPTION_KEYWORDS):
                continue

            if len(u) < 15: 
                continue
                
            clean_subs.append(u)
        except:
            continue

    return list(set(clean_subs))

def get_smallest_msg_id(html):
    """从页面中提取当前最早的消息 ID"""
    soup = BeautifulSoup(html, "html.parser")
    msg_elements = soup.find_all("div", class_="tgme_widget_message", attrs={"data-post": True})
    ids = []
    for el in msg_elements:
        post_attr = el.get("data-post")
        if post_attr and "/" in post_attr:
            try:
                msg_id = int(post_attr.split("/")[-1])
                ids.append(msg_id)
            except:
                continue
    return min(ids) if ids else None

def main():
    if not os.path.exists(CHANNELS_FILE):
        print(f"❌ 配置文件 {CHANNELS_FILE} 不存在")
        return

    with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
        channel_names = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not channel_names:
        print("❌ 频道列表为空")
        return

    all_found_subs = set()
    
    for name in channel_names:
        name = name.lstrip('@')
        print(f"正在抓取频道: {name}")
        
        current_before = ""
        last_before_id = None # 用于防止死循环

        for page in range(MAX_PAGES_PER_CHANNEL):
            full_url = f"{BASE_PREFIX}{name}{current_before}"
            try:
                response = session.get(full_url, timeout=15)
                if response.status_code == 200:
                    subs = extract_links_from_html(response.text)
                    all_found_subs.update(subs)
                    
                    smallest_id = get_smallest_msg_id(response.text)
                    
                    # 校验：翻页逻辑
                    if smallest_id and smallest_id != last_before_id and smallest_id > 1:
                        print(f"  -> 第 {page+1} 页: 发现 {len(subs)} 个符合特征的链接 (before={smallest_id})")
                        current_before = f"?before={smallest_id}"
                        last_before_id = smallest_id
                    else:
                        print(f"  -> 第 {page+1} 页: 结束翻页")
                        break
                        
                    if not subs and page > 1: # 连续多页没东西则停止
                        break
                elif response.status_code == 404:
                    print(f"  -> 频道不存在 (404)")
                    break
                else:
                    print(f"  -> 获取失败 (状态码: {response.status_code})")
                    break
            except Exception as e:
                print(f"  -> 网络错误: {e}")
                break

    print(f"\n[汇总] 共提取出 {len(all_found_subs)} 个唯一订阅链接，正在保存...")

    if all_found_subs:
        with open("valid_subs.txt", "w", encoding="utf-8") as f:
            for u in sorted(list(all_found_subs)):
                f.write(u + "\n")
        print("✅ 已同步所有链接到 valid_subs.txt")
    else:
        print("❌ 未发现任何有效订阅链接")

if __name__ == "__main__":
    main()
