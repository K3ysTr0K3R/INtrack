import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_gpon(ip, ports=None, timeout=10):
    matcher = "<title>GPON Home Gateway</title>"
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f"{port}" for port in ports]
    
    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}"
            headers = {
                'User-Agent': user_agents()
            }
            try:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                if matcher in response.text:
                    print_colour(f"GPON router detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False