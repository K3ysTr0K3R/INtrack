import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_dir_listing(ip, ports=None, timeout=5):
	headers = {"User-Agent": user_agents()}
	matchers = ["Directory listing for ", "Index of /", "[To Parent Directory]", "Directory: /"]
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
				if any(matcher in response.text for matcher in matchers):
					print_colour(f"Directory listing found: {url}")
					return True
			except requests.RequestException:
				continue
	return False
