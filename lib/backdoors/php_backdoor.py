
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def php_backdoor(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    test_params = {
        "cmd": "id",
        "c": "id",
        "command": "id",
        "exec": "id",
        "system": "id",
    }
    
    php_patterns = ["uid=", "gid=", "groups="]
    
    for port in ports:
        for protocol in protocols:
            common_paths = [
                "/index.php", "/admin.php", "/upload.php", "/images/up.php", 
                "/includes/config.php", "/tmp/sess_", "/wp-content/uploads/temp.php"
            ]
            for path in common_paths:
                base_url = f"{protocol}://{ip}{port}{path}"
                for param, value in test_params.items():
                    url = f"{base_url}?{param}={value}"
                    try:
                        response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                        if any(pattern in response.text for pattern in php_patterns):
                            print_colour(f"[+] PHP backdoor detected: {url}")
                            return True
                    except requests.RequestException:
                        continue
    return False