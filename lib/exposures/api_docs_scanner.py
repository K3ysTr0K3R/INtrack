# api_docs_scanner.py
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_api_docs(ip, ports=None, timeout=5):
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    api_paths = [
        "/swagger",
        "/swagger-ui.html",
        "/swagger/index.html",
        "/api-docs",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/swagger.json",
        "/api/swagger",
        "/api/documentation",
        "/api/v1/docs",
        "/api/v2/docs",
        "/api/v3/docs",
        "/swagger/v1/swagger.json",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/v3/swagger.json"
    ]
    
    indicators = [
        "swagger",
        "openapi",
        "API Documentation",
        "Swagger UI",
        "ReDoc",
        "OpenAPI Definition",
        "API Reference",
        "API Explorer"
    ]
    
    for port in ports:
        for protocol in protocols:
            for path in api_paths:
                try:
                    headers = {
                        'User-Agent': user_agents()
                    }
                    url = f"{protocol}://{ip}{port}{path}"
                    response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                    if any(indicator.lower() in response.text.lower() for indicator in indicators):
                        print_colour(f"[+] API Documentation found: {url}")
                        return True
                except requests.RequestException:
                    continue
    return False