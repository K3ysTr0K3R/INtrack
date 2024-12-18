import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def bigip(ip, ports=None, timeout=10):
	headers = {"User-Agent": user_agents()}
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f"{port}" for port in ports]

	for port in ports:
		for protocol in protocols:
			url = f"{protocol}://{ip}{port}"
			try:
				response = requests.get(url, timeout=timeout, verify=False, headers=headers)
				server = response.headers.get('Server', '')
				if "BigIP" in server:
					print_colour(f"{url} - BigIP detected on target")
					return True
			except requests.RequestException:
				continue
	return False