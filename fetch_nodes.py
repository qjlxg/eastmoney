import requests
import re
import os
from bs4 import BeautifulSoup

# =========================
# 配置
# =========================
CHANNELS_FILE = "channels.txt"
BASE_PREFIX = "https://t.me/s/" # 自动补全前缀
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com'
]

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

def extract_links_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()
    urls = re.findall(r'订阅链接[:：]\s*(https?://[^\s\u4e00-\u9fa5]+)', text)
    
    clean_subs = []
    for u in urls:
        clean_url = re.sub(r'[^\w/:.-]+$', '', u)
        if not any(domain in clean_url for domain in BLACKLIST_DOMAINS):
            clean_subs.append(clean_url)
    return list(set(clean_subs))

def main():
    if not os.path.exists(CHANNELS_FILE):
        print(f"❌ 配置文件 {CHANNELS_FILE} 不存在")
        return

    with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
        # 读取频道名称，去除空行和注释
        channel_names = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    all_found_subs = set()
    
    for name in channel_names:
        full_url = f"{BASE_PREFIX}{name}"
        print(f"正在抓取频道: {name}")
        try:
            response = session.get(full_url, timeout=15)
            if response.status_code == 200:
                subs = extract_links_from_html(response.text)
                all_found_subs.update(subs)
                print(f"  -> 发现 {len(subs)} 个链接")
            else:
                print(f"  -> 获取失败 (状态码: {response.status_code})")
        except Exception as e:
            print(f"  -> 网络错误: {e}")

    print(f"\n[汇总] 共发现 {len(all_found_subs)} 个唯一链接，正在保存...")

    if all_found_subs:
        with open("valid_subs.txt", "w", encoding="utf-8") as f:
            for u in sorted(all_found_subs):
                f.write(u + "\n")
        print("✅ 已保存所有链接到 valid_subs.txt")
    else:
        print("❌ 未发现任何链接")

if __name__ == "__main__":
    main()
