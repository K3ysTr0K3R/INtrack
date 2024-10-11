import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_security(ip, ports=None, timeout=10):
	headers = {
	'User-Agent': user_agents()
	}
	paths = ["/security.txt", "/.well-known/security.txt"]
	matcher = ["Contact:", "Expires:"]
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for port in ports:
			for path in paths:
				url = f"{protocol}://{ip}{port}{path}"
				try:
					response = requests.get(url, timeout=timeout, verify=False, headers=headers)
					if any(matchers in response.text for matchers in matcher):
						print_green(f"Security file found: {url}")
						return True
				except requests.RequestException:
					continue
	return False