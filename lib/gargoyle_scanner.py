import requests


matcher = "<title>Gargoyle Router Management Utility</title>"

def check_gargoyle(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = "{protocol}//{ip}{port_suffix}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if matcher in response.text:
                    print(f"[+] Gargoyle device detected: {url}")
            except requests.RequestException:
                continue
    return False
