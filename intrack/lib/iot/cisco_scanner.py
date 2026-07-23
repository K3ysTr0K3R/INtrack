import requests
import urllib3
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_cisco(ip, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    paths = ["/+CSCOE+/logon.html"]
    protocols = ["http", "https"]

    if ports is None:
        ports = [80, 443]
    port_strings = [f":{port}" for port in ports]

    for protocol in protocols:
        for port_str in port_strings:
            for path in paths:
                url = f"{protocol}://{ip}{port_str}{path}"
                try:
                    response = requests.get(
                        url,
                        verify=False,
                        timeout=timeout,
                        headers=headers,
                        allow_redirects=False
                    )

                    if response.status_code not in (200, 302, 401):
                        continue

                    text_lower = response.text.lower()
                    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                    server = headers_lower.get('server', '')
                    x_transid = headers_lower.get('x-transid', '')

                    cisco_cookies = any(
                        cookie.lower().startswith('webvpn') or 'webvpn' in cookie.lower()
                        for cookie in response.cookies.keys()
                    )

                    server_indicator = any(key in server for key in ('cisco', 'asa', 'ios'))

                    transid_indicator = 'cisco' in x_transid or 'asa' in x_transid

                    body_indicators = (
                        ('cisco' in text_lower and ('vpn' in text_lower or 'ssl' in text_lower)) or
                        'config-auth client="vpn"' in text_lower or
                        'action="/+cscoe+/logon.html"' in text_lower or
                        'name="tgroup"' in text_lower or
                        'cisco systems' in text_lower
                    )

                    location = response.headers.get('Location', '').lower()
                    redirect_indicator = 'webvpn' in location or '+cscoe+' in location

                    score = sum([
                        cisco_cookies,
                        server_indicator,
                        transid_indicator,
                        body_indicators,
                        redirect_indicator
                    ])

                    if score >= 2:
                        print_colour(f"[+] Cisco device detected: {url}")
                        return True

                except requests.RequestException:
                    continue

    return False
