import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_jira(ip, ports=None, timeout=5):
	paths = ["/secure/Dashboard.jspa", "/jira/secure/Dashboard.jspa", "/login.jsp"]
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for path in paths:
			url = f"{protocol}://{ip}{port}{path}"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				if "Project Management Software" in response.text:
					print_colour(f"Jira detected: {url}")
					return True
			except requests.RequestException:
				continue
	return False