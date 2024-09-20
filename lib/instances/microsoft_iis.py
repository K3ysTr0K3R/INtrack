import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_microsoft_iis(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            try:
                url = f"{protocol}://{ip}{port_suffix}"
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                server = response.headers.get('Server', '')
                if "IIS" in server:
                    print_green(f"{url} [{server}]")
            except requests.RequestException:
                continue
    return False
