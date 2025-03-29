import mmh3
import requests
import base64
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_hikvision(ip, ports=None, timeout=5):
    headers = {
        "User-Agent": user_agents()
    }
    paths = ["", "/", "/index.asp", "/favicon.ico", "/doc/page/login.asp"]
    matchers = ["Hikvision Digital Technology", "/doc/page/login.asp?_"]
    protocols = ["http", "https"]
    target_favicon_hash = 999357577

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for path in paths:
            for port in ports:
                url = f"{protocol}://{ip}{port}"
                url_ = f"{url}{path}"
                try:
                    response = requests.get(url_, timeout=timeout, verify=False, headers=headers)
                    if response is not None:
                        server = response.headers.get('Server', '')
                        favicon_base64 = base64.b64encode(response.content) if response.content else None
                        favicon_hash = mmh3.hash(favicon_base64.decode('utf-8')) if favicon_base64 else None
                        if response.text and (any(matcher in response.text for matcher in matchers) or "Hikvision-Webs" in server or favicon_hash == target_favicon_hash):
                            print_colour(f"Hikvision device found: {url}")
                            return True

                except requests.RequestException:
                    continue

    return False