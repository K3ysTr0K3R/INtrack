import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def scan_webmin(ip, ports=None, timeout=5):
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}"

            headers = {
                'User-Agent': user_agents()
            }

            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                server = response.headers.get('Server', '')
                if "Webmin" in response.text or "<title>Login to Webmin</title>" in response.text or server == "MiniServ":
                    print_colour(f"Webmin detected: {url} [{server}]")
                    return True
            except requests.RequestException:
                continue

    return False
