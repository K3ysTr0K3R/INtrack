import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_CVE_2022_40684(ip, ports=None, timeout=5):
	headers = {"User-Agent": user_agents()}
	path = "/api/v2/cmdb/system/admin"
	macthers = ["ENC XXXX", "http_method"]
	protocol = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}{path}"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				if any(matcher in response.text for matcher in matchers):
					print_colour(f"The target is vulnerable to CVE-2022-40684 : {url}")
					return True
			except requests.RequestException:
				continue
	return False