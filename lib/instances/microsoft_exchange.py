import requests
from lib.color_handler import print_colour
from lib.headers.headers_handler import user_agents

def check_exchange(ip, ports=None, timeout=10):
	headers = {"User-Agent": user_agents()}
	matchers = ['Outlook', '<title>Exchange Log In</title>', '<title>Microsoft Exchange - Outlook Web Access</title>']
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}/owa/auth/logon.aspx"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				if any(matcher in response.text for matcher in matchers):
					print_colour(f"Microsoft Exchange: {url}")
					return True
			except requests.RequestException:
				continue
	return False