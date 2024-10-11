import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_network_camera(ip, ports=None, timeout=10):
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}/CgiStart?page=Single"
			try:
				response = requests.get(url, verify=False, headers=headers, timeout=timeout)
				if "<TITLE>Network Camera</TITLE>" in response.text:
					print_green(f"Network Camera detected: {url}")
					return True
			except requests.RequestException:
				continue
	return False