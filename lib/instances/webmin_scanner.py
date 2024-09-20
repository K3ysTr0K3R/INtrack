import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def scan_webmin(ip, port=None):
    protocols = ["http", "https"]
    port_suffixes = [f":{port}" if port else ""]

    for protocol in protocols:
        for port_suffix in port_suffixes:
            url = f"{protocol}://{ip}{port_suffix}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                server = response.headers.get('Server', '')


                if "Webmin" in response.text or "<title>Login to Webmin</title>" in response.text or server == "MiniServ":
                    print_green(f"Webmin detected: {url} [{server}]")
                    return True
            except requests.RequestException:
                continue

    return False
