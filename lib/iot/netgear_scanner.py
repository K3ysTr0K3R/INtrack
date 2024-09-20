import requests

def scan_netgear(ip, port=False):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                if "NETGEAR" in response.text:
                    print(f"NETGEAR router found: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
