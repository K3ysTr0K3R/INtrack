import requests
from intrack.lib.color_handler import print_colour

def check_CVE_2015_1635(ip, ports=None, timeout=5):
    headers = {"Range": "bytes=0-18446744073709551615"}
    matchers = ["HTTP Error 416", "The requested range is not satisfiable"]
    protocols = ["http", "https"]
    if ports is None:
       ports = [80]
    else:
       ports = [f":{port}" for port in ports]
    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}"
            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if any(matcher in response.text for matcher in matchers) and response.status_code == 416:
                    print_colour(f"The target is vulnerable to CVE-2015-1635 : {url}")
                    return True
            except requests.RequestException:
                continue
    return False
