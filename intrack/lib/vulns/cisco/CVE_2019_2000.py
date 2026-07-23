import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2019_2000(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    paths = ["/prime/admin", "/webacs", "/webacs/welcomeAction.do"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [443, 8443]
    else:
        ports = [f":{port}" for port in ports]
        
    for protocol in protocols:
        for port in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if "Cisco Prime Infrastructure" in response.text:
                        print_colour(f"[+] Detected Cisco Prime Infrastructure, potentially vulnerable to CVE-2019-2000: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False 