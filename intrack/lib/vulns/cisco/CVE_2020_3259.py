import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2020_3259(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    path = "/crossdomain.xml"
    fingerprint_paths = ["/webui/logon.html", "/webui/", "/api/v1/"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [80, 443]
    else:
        ports = [f":{port}" for port in ports]
        
    for protocol in protocols:
        for port in ports:
            # First check if it's IOS XR
            is_ios_xr = False
            for fp_path in fingerprint_paths:
                fp_url = f"{protocol}://{ip}{port}{fp_path}"
                try:
                    response = requests.get(fp_url, verify=False, timeout=timeout, headers=headers)
                    if "Cisco IOS XR" in response.text or "IOS-XR" in response.text:
                        is_ios_xr = True
                        break
                except requests.RequestException:
                    continue
                
            if is_ios_xr:
                # Check for vulnerability
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if response.status_code == 200 and "<allow-access-from domain=\"*\"" in response.text:
                        print_colour(f"[+] Target may be vulnerable to CVE-2020-3259 (Cisco IOS XR RCE): {url}")
                        return True
                except requests.RequestException:
                    continue
    return False 