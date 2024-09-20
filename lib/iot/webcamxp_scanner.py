import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

path = "/mobile.html"
matchers = ["webcams and ip cameras server for windows", "Please provide a valid username/password to access this server."]

def check_webcamxp(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}{path}"
            try:
                response = requests.get(url + path, timeout=5, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print(f"[+] WebcamXP detected: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
