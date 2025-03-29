import re
import requests

CVE_PATHS = {
    "CVE_2023_41265": "/resources/qmc/fonts/CVE-2023-41265.ttf",
    "CVE_2023_29357": "/_api/web/siteusers",
    "CVE_2021_38647": "/wsman",
    "CVE_2021_34473": "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com",
    "CVE_2021_26855": "/owa/auth/x.js"
}

def microsoft_worm(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    
    for protocol in protocols:
        for port_prefix in ports:
            for path in CVE_PATHS.values():
                url = f"{protocol}://{ip}{port_prefix}"
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    server = response.headers.get('Server', '')
                    if "IIS" in server:
                        url_base = f"{protocol}://{ip}{port_prefix}"
                        extracted_ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url_base)
                        if extracted_ip:
                            extracted_ip = extracted_ip[0]
                            exchange_panel_url = f"{url_base}/owa/auth/logon.aspx?replaceCurrent=1&url=http://{extracted_ip}/ecp"
                            exchange_response = requests.get(exchange_panel_url, timeout=10, verify=False)
                            if 'Exchange Admin Center' in exchange_response.text and exchange_response.status_code == 200:
                                print(f"[+] Microsoft Exchange Panel found: {url_base}")
                                web_services = ["/EWS/Exchange.asmx", "/owa/service.svc"]
                                for service_path in web_services:
                                    service_url = f"{url_base}{service_path}"
                                    service_response = requests.get(service_url, timeout=10, verify=False)
                                    if 'X-Owa-Version' in service_response.headers:
                                        print(f"[+] Microsoft Exchange Web Service found: {service_url}")
                except requests.RequestException:
                    continue
