import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

matchers = ["WordPress</title>", "/wp-login.php?action=lostpassword"]

def check_wordpress(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}/wp-login.php"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print_green(f"Found WordPress site: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
