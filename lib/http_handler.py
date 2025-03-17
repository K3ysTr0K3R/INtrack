import requests

def http_https(ip, timeout=5):
    http_url = f"http://{ip}"
    https_url = f"https://{ip}"

    try:
        requests.get(https_url, timeout=timeout, verify=False)
        return {"protocol": "https"}
    except requests.RequestException:
        pass

    try:
        requests.get(http_url, timeout=timeout, verify=False)
        return {"protocol": "http"}
    except requests.RequestException:
        pass
    return None