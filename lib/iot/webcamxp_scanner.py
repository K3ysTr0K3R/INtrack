import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

path = "/mobile.html"
matchers = ["webcams and ip cameras server for windows", "Please provide a valid username/password to access this server."]

def check_webcamxp(ip, ports=None, timeout=5):
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
                response = requests.get(url + path, headers=headers, timeout=timeout, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print_colour(f"[+] WebcamXP detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False