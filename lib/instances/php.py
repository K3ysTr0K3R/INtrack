import requests

def php(ip, ports=None, timeout=10):
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for port in ports:
		for protocol in protocols:
			url = f"{protocol}://{ip}{port}"
			try:
				response = requests.head(url, timeout=10, verify=False)
				server_header = response.headers.get("Server", "")
				power_header = response.headers.get("X-Powered-By", "")
				if "PHP" in server_header or "PHP" in power_header:
					print(f"PHP Detected: {ip}")
					return True
			except requests.RequestException:
				continue
	return False