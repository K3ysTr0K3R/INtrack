import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

matcher = "<title>GPON Home Gateway</title>"

def check_gpon(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if matcher in response.text:
                    print_green(f"GPON router detected: {url}")
            except requests.RequestException:
                continue
    return False
