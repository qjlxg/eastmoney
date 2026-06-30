import requests
import re
from bs4 import BeautifulSoup

# =========================
# 配置
# =========================
BASE_URL = "https://t.me/s/freeVPNjd"
BLACKLIST_DOMAINS = [
    't.me', 'github.com', 'google.com', 'youtube.com', 
    'twitter.com', 'facebook.com', 'telegra.ph', 'instagram.com'
]

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

# =========================
# 提取并清理链接 (不进行有效性校验)
# =========================
def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text()
    
    # 精准匹配“订阅链接：”后的 URL
    urls = re.findall(r'订阅链接[:：]\s*(https?://[^\s\u4e00-\u9fa5]+)', text)
    
    final_subs = []
    for u in urls:
        # 清洗末尾干扰字符
        clean_url = re.sub(r'[^\w/:.-]+$', '', u)
        # 黑名单过滤
        if not any(domain in clean_url for domain in BLACKLIST_DOMAINS):
            final_subs.append(clean_url)
            
    return list(set(final_subs))

# =========================
# 主流程
# =========================
def main():
    print("[1] 获取频道内容...")
    try:
        response = session.get(BASE_URL, timeout=15)
        if response.status_code != 200:
            print("❌ 获取失败")
            return
    except Exception as e:
        print(f"❌ 网络错误: {e}")
        return

    print("[2] 提取所有链接...")
    subs = extract_links(response.text)
    
    print(f"[3] 共发现 {len(subs)} 个链接，直接保存...")

    if subs:
        with open("valid_subs.txt", "w", encoding="utf-8") as f:
            for u in sorted(subs):
                f.write(u + "\n")
        print("✅ 已保存所有链接到 valid_subs.txt")
    else:
        print("❌ 未发现任何链接")

if __name__ == "__main__":
    main()
