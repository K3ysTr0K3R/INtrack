import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_CVE_2021_34473(ip, ports=None, timeout=5):
	headers = {"User-Agent": user_agents()}
	paths = ["/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com", "/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com"]
	matchers = ["Microsoft.Exchange.Clients.Owa2.Server.Core.OwaADUserNotFoundException", "Exchange MAPI/HTTP Connectivity Endpoint"]
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for path in paths:
			for port in ports:
				url = f"{protocol}://{ip}{port}{path}"
				try:
					response = requests.get(url, verify=False, timeout=timeout, headers=headers)
					if response.text and any(matcher in response.text for matcher in matchers):
						print_colour(f"The target is vulnerable to CVE-2021-34473 : {url}")
						return True
				except requests.RequestException:
					continue
	return False