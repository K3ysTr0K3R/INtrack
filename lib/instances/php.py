import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def php(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}"
            try:
                response = requests.head(url, timeout=timeout, verify=False, headers=headers)
                server_header = response.headers.get("Server", "")
                power_header = response.headers.get("X-Powered-By", "")
                
                if "PHP" in server_header or "PHP" in power_header:
                    print_colour(f"[+] PHP Detected: {url} (via headers)")
                    return True
                
                php_files = ["/index.php", "/info.php", "/phpinfo.php", "/test.php", "/admin.php", "/wp-login.php"]
                for php_file in php_files:
                    file_url = f"{url}{php_file}"
                    try:
                        file_response = requests.get(file_url, timeout=timeout, verify=False, headers=headers)
                        if file_response.status_code == 200 and any(marker in file_response.text for marker in ["PHP Version", "<? php", "<?php"]):
                            print_colour(f"[+] PHP Detected: {file_url}")
                            return True
                    except requests.RequestException:
                        continue
                    
            except requests.RequestException:
                continue
    return False