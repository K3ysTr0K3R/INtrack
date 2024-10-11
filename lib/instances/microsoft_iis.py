import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_microsoft_iis(ip, ports=None, timeout=10):
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            try:
                url = f"{protocol}://{ip}{port}"
                headers = {
                    'User-Agent': user_agents()
                }
                response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
                server = response.headers.get('Server', '')
                if "IIS" in server:
                    print_green(f"{url} [{server}]")
                    return True
            except requests.RequestException:
                continue
    return False