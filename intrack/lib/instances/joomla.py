import re
import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_joomla(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    matchers = ["<version>", "<creationDate>", "</metafile>"]
    paths = ["/administrator/manifests/files/joomla.xml","/language/en-GB/en-GB.xml","/README.txt","/modules/custom.xml"]
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, verify=False, timeout=timeout, headers=headers)
                    if any(matcher in response.text for matcher in matchers):
                        print_colour(f"Joomla instance detected: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False