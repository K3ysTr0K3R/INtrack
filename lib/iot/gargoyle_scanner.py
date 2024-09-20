import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

matcher = "<title>Gargoyle Router Management Utility</title>"

def check_gargoyle(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if matcher in response.text:
                    print_green(f"Gargoyle device detected: {url}")
                    return True
            except requests.RequestException as e:
                continue
    return False
