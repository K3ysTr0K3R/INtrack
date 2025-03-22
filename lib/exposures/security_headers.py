import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def header_definitions(header: str):
    if header == "Strict-Transport-Security":
        return "Prevents browsers from connecting to a site over HTTP. Forces the browser to connect to the site over HTTPS."
    elif header == "X-Frame-Options":
        return "Prevents clickjacking attacks by restricting the ability of a page to be embedded into other sites."
    elif header == "X-XSS-Protection":
        return "Prevents XSS attacks by blocking scripts that are not in the Content-Security-Policy."
    elif header == "X-Content-Type-Options":
        return "Prevents MIME type sniffing attacks."
    elif header == "Referrer-Policy":
        return "Controls the value of the Referrer header."
    elif header == "Content-Security-Policy":
        return "Controls the sources of content that can be loaded in the browser."
    elif header == "Permissions-Policy":
        return "Controls the features of the browser that can be used."
    elif header == "Feature-Policy":
        return "Controls the features of the browser that can be used."
    elif header == "Expect-CT":
        return "Enables the Expect-CT header to be sent to the browser."


def check_security_headers(ip, ports=None, timeout=5):
    headers = {
        'User-Agent': user_agents()
    }
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    security_headers = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Permissions-Policy",
        "Feature-Policy",
        "Expect-CT",
    ]

    for port in ports:
        for protocol in protocols:
            for header in security_headers:
                url = f"{protocol}://{ip}{port}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if header not in response.headers:
                        print_colour(f"[+] Security header missing: {header}")
                        print_colour(f"[+] Definition: {header_definitions(header)}")
                        return True
                except requests.RequestException:
                    continue
    return False
