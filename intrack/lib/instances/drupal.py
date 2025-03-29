import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_drupal(ip, ports=None, timeout=5):
    headers = {
        "User-Agent": user_agents()
    }
    paths = ["", "/CHANGELOG.txt", "/core/install.php"]
    matchers = ["Initial release", "Drupal 1.0.0", "Drupal"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for path in paths:
            for port in ports:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if response and response.text and any(matcher in response.text for matcher in matchers):
                        print_colour(f"Drupal detected: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False
