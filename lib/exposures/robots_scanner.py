import requests

def check_robots(ip, port=None):
    matchers = ["User-agent:", "Disallow:", "Allow:"]
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            try:
                url = f"{protocol}://{ip}{port_suffix}/robots.txt"
                response = requests.get(url, timeout=10, verify=False)
                if any(matcher in response.text for matcher in matchers):
                    print(f"Robots file found: {url}")
                    return True
            except requests.RequestException:
                continue
    return False
