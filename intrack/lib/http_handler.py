import requests

def http_https(ip: str, timeout: int = 5) -> dict | None:
    for scheme in ("https", "http"):
        try:
            requests.get(f"{scheme}://{ip}", timeout=timeout, verify=False)
            return {"protocol": scheme}
        except requests.RequestException:
            continue
    return None
