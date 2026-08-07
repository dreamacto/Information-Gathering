import requests, re, urllib3
urllib3.disable_warnings()
h = {'User-Agent': 'Mozilla/5.0 Chrome/120'}

targets = [
    ('wzlxq', 'http://www.wzlxq.gov.cn', '梧州龙圩区政府'),
    ('gxbssyy', 'https://www.gxbssyy.com', '百色市人民医院'),
    ('guet', 'https://www.guet.edu.cn', '桂林电子科技大学'),
    ('glrcw', 'https://www.glrcw.com', '桂林盛才人力'),
    ('runjian', 'https://www.runjian.com', '润建股份'),
    ('liuzhousteel', 'https://www.liuzhousteel.com', '柳州钢铁'),
    ('liugong', 'https://www.liugong.cn', '柳工机械'),
    ('jjr', 'http://www.jjr.com.cn', '捷佳润科技'),
    ('cloudbae', 'https://www.cloudbae.cn', '云宝宝大数据'),
    ('bossco', 'https://www.bossco.cc', '博世科环保'),
    ('gxyxsh', 'https://www.gxyxsh.com', '耀象文化'),
    ('gxetc', 'https://www.gxetc.com.cn', '捷通高速'),
    ('bbgdex', 'https://www.bbgdex.com', '北部湾大数据'),
    ('gxbtxc', 'https://www.gxbtxc.com', '北投信创'),
    ('manascloud', 'https://www.manascloud.com', '七识数字'),
    ('gxzyy', 'https://www.gxzyy.com.cn', '广西中医药大学一附院'),
    ('gxlqjs', 'https://www.gxlqjs.com', '广西路建工程'),
    ('nnmzj', 'https://mzj.nanning.gov.cn', '南宁市民政局'),
]

search_paths = [
    '/search.jsp?q=AI', '/search?q=AI', '/search/?q=AI',
    '/plus/search.php?q=AI', '/index.php?m=search&q=AI',
    '/search/index?q=AI', '/so/?q=AI', '/ss/?q=AI',
]

for abbr, base, name in targets:
    found = False
    for sp in search_paths:
        try:
            url = base.rstrip('/') + sp
            r = requests.get(url, timeout=6, headers=h, verify=False)
            if r.status_code != 200 or len(r.text) < 500:
                continue
            # find links containing AI
            pattern = r'<a[^>]+href\s*=\s*"([^"]+)"[^>]*>([^<]*)'
            matches = re.findall(pattern, r.text[:10000], re.I)
            ai_matches = [(href, text) for href, text in matches
                         if 'AI' in (href + text) or 'ai' in href.lower()]
            if ai_matches:
                print('[%s] %d AI results' % (abbr, len(ai_matches)))
                for href, text in ai_matches[:3]:
                    print('  ' + text.strip()[:60] + ' -> ' + href[:60])
                found = True
                break
        except:
            pass
    if not found:
        pass  # quiet

print('\nDone')
