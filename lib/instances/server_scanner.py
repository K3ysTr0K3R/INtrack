import re
import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_servers(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    
    for protocol in protocols:
        for port_suffix in ports:
            try:
                url = f"{protocol}://{ip}{port_suffix}"
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                
                http_element = re.findall(r'<title>(.*)</title>', response.text)
                http_title = http_element[0] if http_element else "No title found"
                
                server = response.headers.get('Server', 'No server header')
                status_code = response.status_code
                
                print_green(f"{url} [{status_code}] [{server}] [{http_title}]")
            
            except requests.RequestException:
                continue
                
    return False
