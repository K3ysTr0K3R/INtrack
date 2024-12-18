import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_ncast(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}"
            try:
                response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                if "Ncast" in response.text:
                    print_colour(f"Ncast detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False