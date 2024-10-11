import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_cisco(ip, ports=None, timeout=timeout):
    headers = {"User-Agent": user_agents()}
    paths = ["", "/Login.aspx", "/+CSCOE+/logon.html"]
    protocols ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        for port in ports:
            for path in paths
            url = f"{protocol}://{ip}{port}{path}"
            try:
                response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                server = response.headers.get('Server', '')
                if 'config-auth client="vpn"' or "Cisco" in response.text or "CISCO" in server:
                    print_green(f"Cisco device detected: {url}")
                    return True
            except request.RequestException:
                continue
    return False