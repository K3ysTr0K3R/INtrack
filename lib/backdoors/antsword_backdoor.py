import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def antsword_backdoor(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}/.antproxy.php"
            try:
                data = "ant": 'echo md5("antproxy.php");'
                response = requests.post(url, data=data, verify=False, timeout=timeout, headers=headers)
                if "951d11e51392117311602d0c25435d7f" in response.text:
                    print_green(f"AntSword backdoor detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
