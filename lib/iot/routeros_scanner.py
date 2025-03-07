import re
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def mikrotik_router(ip, ports=None, timeout=5):
	headers = {'User-Agent': user_agents()}
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				version = re.findall(r"<h1>RouterOS v(.+)<\/h1>", response.text)
				if "RouterOS" or "<title>RouterOS router configuration page</title>" in response.text:
					if version:
						version_clean = version[0]
						print_colour(f"[+] {url} - RouterOS detected (MikroTik router) ({version_clean})")
					else:
						print_colour(f"[+] {url} - RouterOS detected (MikroTik router)")
					return True
			except requests.RequestException:
				continue
	return False