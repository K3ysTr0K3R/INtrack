import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_paths(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    paths = ["/nginx.conf", "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf"]
    matchers = ["nginx", "nginx/"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    s = requests.Session()
    for protocol in protocols:
        for port in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    r = s.get(url, timeout=timeout, headers=headers)
                    if r.status_code == 200:
                        if any(matcher in r.text for matcher in matchers):
                            print_colour(f"Nginx detected: {url}")
                            return True
                except requests.RequestException:
                    continue
    return False


def check_server_header(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    matchers = ["nginx", "Nginx"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    s = requests.Session()
    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}"
            try:
                r = s.get(url, timeout=timeout, headers=headers)
                for k, v in r.headers.items():
                    if k.lower() == "server":
                        if any(matcher in v for matcher in matchers):
                            print_colour(f"Nginx detected: {url}")
                            return True
            except requests.RequestException:
                continue
    return False


def check_nginx(ip, ports=None, timeout=5):
    if check_paths(ip, ports, timeout):
        return True
    if check_server_header(ip, ports, timeout):
        return True
    return False
