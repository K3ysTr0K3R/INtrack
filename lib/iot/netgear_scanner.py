import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def scan_netgear(ip, ports=False, timeout=10):
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port_suffix}"
            headers = {
                'User-Agent': user_agents()
            }
            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if "NETGEAR" in response.text:
                    print_green(f"NETGEAR router found: {url}")
                    return True
            except requests.RequestException:
                continue
    return False