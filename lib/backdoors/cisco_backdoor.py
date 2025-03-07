import re
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def cisco_backdoor(ip, ports=None, timeout=5):
    headers = {
        "User-Agent": user_agents(),
        "Authorization": "0ff4fbf0ecffa77ce8d3852a29263e263838e9bb"
    }

    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for path in paths:
        for port in ports:
            for protocol in protocols:
                get = f"{protocol}://{ip}{port}/webui"
                post = f"{protocol}://{ip}{port}/webui/logoutconfirm.html?logon_hash=1"
                try:
                    response_get = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    response_post = requests.post(url, verify=False, timeout=timeout, headers=headers)
                    if re.search(r'webui-centerpanel-title', response_get.text) or re.search(r'^([a-f0-9]{18})\s*$', response_get.text):
                        print_colour(f"[+] Cisco backdoor detected: {url}")
                        return True
                    if re.search(r'webui-centerpanel-title', response_post.text) or re.search(r'^([a-f0-9]{18})\s*$', response_post.text):
                        print_colour(f"[+] Cisco backdoor detected: {url}")
                        return True
                    except requests.RequestException:
                        continue
     return False
