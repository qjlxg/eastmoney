import requests
import re
import os
import base64
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor

# =========================
# 配置
# =========================
CHANNELS_FILE = "channels.txt"
BASE_PREFIX = "https://t.me/s/" # 自动补全前缀
MAX_PAGES_PER_CHANNEL = 58     # 每个频道向后翻页的数量

# 订阅特征关键字 (URL 包含以下任意词汇将被优先视为订阅链接)
SUBSCRIPTION_KEYWORDS = [
    'sub', 'subscribe', 'token', 'clash', 'v2ray', 'singbox', 
    'base64', 'raw', 'link', 'config', 'proxypool', 'node', 
    'api/v1', 'yaml', 'yml', 'json', 'txt'
]

# 支持的协议列表
ALLOWED_SCHEMES = [
    'http', 'https', 'clash', 'v2ray', 'ss', 'ssr', 
    'trojan', 'tuic', 'hysteria', 'vless', 'vmess', 'sing-box'
]

# 屏蔽非订阅类域名
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 'youtu.be','chibaba.ggff.net','Amirinventor2010.bio.link','apkdl.net','paste.gg',
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com','githubusercontent','raw.githubusercontent.com','libredns.gr',
    'www.xrayvip.com', 'link.onesy.link', 'wikipedia.org', 'reddit.com',
    'apple.com', 'microsoft.com', 'purl.org', 'w3.org', 'x.com',
    'chatgpt.com', 'claude.ai', 'deepseek.com', 'openai.com', 'perplexity.ai',
    'speedtest.net', 'fast.com', 'spotify.com', 'soundcloud.com',
    'aparat.com', 'rubika.ir', 'uupload.ir', 'uploadboy.com', 'uplod.ir',
    'post.ir', 'cafebazaar.ir', 'snapp.ir', 'arvancloud.ir', 'bertina.ir',
    'radiojavan.com', 'mega.nz', 'f-droid.org', 'visualstudio.com', 'nextjs.org',
    'kubernetes.io', 'helm.sh', 'cloudflarestatus.com', 'reuters.com'
]

# 屏蔽常见静态资源后缀
BLACKLIST_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
    '.mp4', '.mp3', '.m4a', '.pdf', '.exe', '.dmg', '.apk', 
    '.zip', '.rar', '.7z', '.sh'
]

# 屏蔽保留/虚假 IP 
BLACKLIST_IPS = ['0.0.0.0', '1.0.0.0', '127.0.0.1', '8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4']

session = requests.Session()
# 增加重试机制：处理 429 (频率限制) 和 5xx 错误
retries = Retry(total=3, backoff_factor=1.0, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
})

def b64_decode(data):
    """尝试解码 Base64 字符串，增强协议识别"""
    try:
        # 清理可能存在的干扰字符
        data = re.sub(r'[^a-zA-Z0-9+/=]', '', data.strip().replace('-', '+').replace('_', '/'))
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(data).decode('utf-8', 'ignore')
        # 兼容多种订阅协议头
        if any(decoded.startswith(p) for p in ALLOWED_SCHEMES):
            return decoded
    except:
        pass
    return None

def clean_url_params(url_str):
    """剔除随机参数以实现精准去重，保留关键参数"""
    try:
        parsed = urlparse(url_str)
        if not parsed.query:
            return url_str
        
        query_params = parse_qs(parsed.query)
        # 常见随机干扰参数列表
        noise_params = {'t', 'time', 'ts', 'timestamp', 'cache', 'random', 'rng', '_'}
        
        filtered_params = {k: v for k, v in query_params.items() if k.lower() not in noise_params}
        
        if not filtered_params:
            return urlunparse(parsed._replace(query=""))
        
        new_query = urlencode(filtered_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except:
        return url_str

def extract_links_from_html(html):
    """多维度提取逻辑：HTML属性 + 正文正则 + Base64识别"""
    soup = BeautifulSoup(html, "html.parser")
    found_raw_urls = []

    # 1. 提取所有 <a> 标签的超链接
    for a in soup.find_all('a', href=True):
        found_raw_urls.append(a['href'])

    # 2. 提取文本中所有的裸链接 (非捕获组优化正则)
    text = soup.get_text()
    protocol_regex = r'(?:' + '|'.join(ALLOWED_SCHEMES) + r')://[^\s<>"\']+'
    raw_text_urls = re.findall(protocol_regex, text)
    found_raw_urls.extend(raw_text_urls)

    # 3. 提取可能的 Base64 编码链接
    # 增加对常见 Base64 特征的识别
    b64_blocks = re.findall(r'[a-zA-Z0-9+/=]{24,}', text)
    for block in b64_blocks:
        decoded = b64_decode(block)
        if decoded:
            found_raw_urls.append(decoded)

    clean_subs = []
    lower_blacklist = [d.lower() for d in BLACKLIST_DOMAINS]

    for u in found_raw_urls:
        # 清理非 ASCII 字符和尾部干扰
        u = re.split(r'[^\x00-\x7F]+', u)[0]
        u = u.strip().rstrip(').,;!]>》】"\'#')
        
        try:
            parsed = urlparse(u)
            if not parsed.scheme: continue
            
            # 协议过滤
            scheme = parsed.scheme.lower()
            if scheme not in ALLOWED_SCHEMES: continue

            # 执行去重清洗
            u = clean_url_params(u)
            u_lower = u.lower()
            
            # 1. 黑名单域名过滤
            if any(blk in u_lower for blk in lower_blacklist): continue
            
            # 2. IP 黑名单
            domain = parsed.netloc.split(':')[0]
            if domain in BLACKLIST_IPS: continue
            
            # 3. 后缀名过滤
            if any(parsed.path.lower().endswith(ext) for ext in BLACKLIST_EXTENSIONS): continue
            
            # 4. 关键字检查 (仅针对 http/https 协议强制检查)
            if scheme in ['http', 'https']:
                if not any(kw in u_lower for kw in SUBSCRIPTION_KEYWORDS):
                    continue
            
            if len(u) < 15: continue
                
            clean_subs.append(u)
        except:
            continue

    return list(set(clean_subs))

def get_smallest_msg_id(html):
    """提取页面中最小的消息ID用于翻页"""
    try:
        soup = BeautifulSoup(html, "html.parser")
        msg_elements = soup.find_all("div", class_="tgme_widget_message", attrs={"data-post": True})
        ids = []
        for el in msg_elements:
            attr = el.get("data-post", "")
            if "/" in attr:
                try:
                    ids.append(int(attr.split("/")[-1]))
                except: continue
        return min(ids) if ids else None
    except:
        return None

def process_channel(name):
    """单个频道的抓取逻辑"""
    name = name.lstrip('@').strip()
    if not name: return set()
    
    print(f"正在抓取频道: {name}")
    channel_subs = set()
    current_before = ""
    last_before_id = None 

    for page in range(MAX_PAGES_PER_CHANNEL):
        # 动态延迟：第1页后开始随机等待，模拟真人行为
        if page > 0:
            time.sleep(random.uniform(1.5, 3.5))
            
        full_url = f"{BASE_PREFIX}{name}{current_before}"
        try:
            response = session.get(full_url, timeout=15)
            if response.status_code == 200:
                subs = extract_links_from_html(response.text)
                channel_subs.update(subs)
                
                smallest_id = get_smallest_msg_id(response.text)
                
                if smallest_id and smallest_id != last_before_id and smallest_id > 1:
                    print(f"  -> {name} 第 {page+1} 页: 发现 {len(subs)} 个有效链接 (before={smallest_id})")
                    current_before = f"?before={smallest_id}"
                    last_before_id = smallest_id
                else:
                    print(f"  -> {name} 第 {page+1} 页: 到底了或无更多消息")
                    break
            elif response.status_code == 429:
                print(f"  -> {name} 触发频率限制 (429)，停止该频道抓取")
                break
            else:
                print(f"  -> {name} 请求失败 (状态码: {response.status_code})")
                break
        except Exception as e:
            print(f"  -> {name} 异常: {e}")
            break
    return channel_subs

def main():
    if not os.path.exists(CHANNELS_FILE):
        print(f"❌ 配置文件 {CHANNELS_FILE} 不存在")
        return

    try:
        with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
            channel_names = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"❌ 读取配置文件失败: {e}")
        return

    if not channel_names:
        print("❌ 频道列表为空")
        return

    all_found_subs = set()
    
    # 线程池并发处理
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(process_channel, channel_names)
        for subs in results:
            all_found_subs.update(subs)

    print(f"\n[汇总] 共提取出 {len(all_found_subs)} 个唯一订阅链接")
    
    if all_found_subs:
        try:
            with open("valid_subs.txt", "w", encoding="utf-8") as f:
                for u in sorted(list(all_found_subs)):
                    f.write(u + "\n")
            print("✅ 任务完成，结果已保存到 valid_subs.txt")
        except Exception as e:
            print(f"❌ 保存文件失败: {e}")
    else:
        print("❌ 未发现任何有效订阅链接")

if __name__ == "__main__":
    main()
