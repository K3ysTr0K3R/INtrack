import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_epmp(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        url = f"{protocol}://{ip}{port}"
        try:
            response = requests.get(url, timeout=timeout, verify=False, headers=headers)
            if "<title>ePMP</title>" in response.text:
                print_green(f"ePMP detected: {url}")
                return True
        except requests.RequestException:
            continue
    return False