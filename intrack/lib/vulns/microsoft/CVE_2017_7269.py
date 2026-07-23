import requests
import re
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2017_7269(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}"
            try:
                response = requests.options(url, verify=False, timeout=timeout, headers=headers)
                dav_sql_match = re.search(r"<DAV:sql>", response.text)
                dav_version_match = re.search(r"[\d]+(,\s+[\d]+)?", response.headers.get("dav", ""))
                propfind_public_match = re.search(r".*?PROPFIND", response.headers.get("public", ""))
                propfind_allow_match = re.search(r".*?PROPFIND", response.headers.get("allow", ""))

                dsl_condition = any([
                    dav_sql_match, 
                    dav_version_match, 
                    propfind_public_match, 
                    propfind_allow_match
                ])

                if "IIS/6.0" in response.headers.get("server", "") and dsl_condition:
                    print_colour(f"The target is vulnerable to CVE-2017-7269 : {url}")
                    return True
            except requests.RequestException:
                continue
    
    return False
