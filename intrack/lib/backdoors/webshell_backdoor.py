import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def webshell_backdoor(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    webshell_patterns = ["uname -a", "file_put_contents", "shell_exec", "system(", 
                        "FilesManager", "password", "passthru", "Terminal", "exec(", "eval("]
    
    for port in ports:
        for protocol in protocols:
            base_url = f"{protocol}://{ip}{port}"
            for pattern in webshell_patterns:
                url = f"{base_url}/{pattern}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200:
                        print_colour(f"[+] Webshell found: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False
    