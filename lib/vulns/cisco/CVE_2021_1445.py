import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_CVE_2021_1445(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    paths = ["/api/sslvpn_websession", "/jboss-net/", "/dana-admin/"]
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
                    if response.status_code == 200 and any(model in response.text for model in ["RV340", "RV345", "RV160", "RV260"]):
                        print_colour(f"[+] Target may be vulnerable to CVE-2021-1445 (Cisco RV Authentication Bypass): {url}")
                        return True
                except requests.RequestException:
                    continue
    return False 