import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

matchers = ["WordPress</title>", "/wp-login.php?action=lostpassword"]

def check_wordpress(ip, ports=None, timeout=10):
    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}/wp-login.php"
            headers = {
                'User-Agent': user_agents()
            }
            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print_colour(f"Found WordPress site: {url}")
                    return True
            except requests.RequestException:
                continue
    return False