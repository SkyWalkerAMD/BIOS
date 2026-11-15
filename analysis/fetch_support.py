from pathlib import Path
import urllib.request
import re
from concurrent.futures import ThreadPoolExecutor

BASE = Path(__file__).resolve().parent
PAGES = {
    'hero': 'https://www.asus.com/us/supportonly/rog%20maximus%20z790%20hero/helpdesk_bios/',
    'proart': 'https://www.asus.com/us/supportonly/proart%20z790-creator%20wifi/helpdesk_bios/',
    'manual': 'https://www.asus.com/us/supportonly/ipmi%20expansion%20card/helpdesk_manual/',
}

def fetch(item):
    name, url = item
    try:
        data = urllib.request.urlopen(url, timeout=25).read().decode('utf-8')
        (BASE / ('asus_' + name + '.html')).write_text(data, encoding='utf-8')
        urls = sorted(set(re.findall(r'https[^\s"<>]+?(?:\.zip|\.pdf)', data.replace('\\u002F', '/').replace('\\/', '/'))))
        return name, urls, len(data)
    except Exception as e:
        return name, str(e)

for result in ThreadPoolExecutor(3).map(fetch, PAGES.items()):
    print(result)
