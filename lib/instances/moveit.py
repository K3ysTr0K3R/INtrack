import requests
from lib.color_handler import print_colour
from lib.headers.headers_handler import user_agents

def check_moveit(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    matchers = ["stylesheet_MOVEit", "moveit.transfer", "MOVEitPopUp", "MOVEit Automation"]
    path = ["", "/human.aspx"]
    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    for protocol in protocols:
        for port in ports:
            for paths in path:
                try:
                    url = f"{protocol}://{ip}{port}{paths}"
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if any(matcher in response.text for matcher in matchers):
                        print_colour(f"[+] {url} - Moveit detected")
                        return True
                except requests.RequestException:
                    continue
    return False