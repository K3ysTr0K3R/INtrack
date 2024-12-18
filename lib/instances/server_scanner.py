import re
import requests
from lib.headers.headers_handler import user_agents  
from lib.color_handler import print_colour

def check_servers(ip, ports=None, timeout=10):
    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for port in ports:
        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}{port}"
                
                headers = {
                    'User-Agent': user_agents()
                }

                response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)

                http_element = re.findall(r'<title>(.*)</title>', response.text)
                http_title = http_element[0] if http_element else "No title found"

                server = response.headers.get('Server', 'No server header')
                status_code = response.status_code

                print_colour(f"[+] {url} [{status_code}] [{server}] [{http_title}]")
                return True

            except requests.RequestException:
                continue

    return False