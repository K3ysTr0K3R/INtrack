import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_epmp(ip, ports=None, timeout=5):
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
                print_colour(f"ePMP detected: {url}")
                return True
        except requests.RequestException:
            continue
    return False