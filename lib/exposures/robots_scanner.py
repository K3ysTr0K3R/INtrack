import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_robots(ip, ports=None, timeout=10):
    matchers = ["User-agent:", "Disallow:", "Allow:"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else: 
        ports = [f":{port}" for port in ports]
    
    for port in ports:
        for protocol in protocols:
            try:
                headers = {
                    'User-Agent': user_agents()
                }
                url = f"{protocol}://{ip}{port}/robots.txt"
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print_colour(f"Robots file found: {url}")
                    return True
            except requests.RequestException:
                continue
    return False