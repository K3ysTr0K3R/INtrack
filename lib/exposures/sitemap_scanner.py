import requests 
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_sitemap(ip, ports=None, timeout=10):
	headers = {"User-Agent": user_agents()}
	paths = ["/sitemap.xml", "/sitemap.xsl", "/sitemap.xsd"]
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for port in ports:
		for protocol in protocols:
			for path in paths:
				url = f"{protocol}://{ip}{port}{path}"
				try:
					response = requests.get(url, verify=False, timeout=timeout, headers=headers)
					if "sitemap>" in response.text:
						print_green(f"Sitemap file found: {url}")
						return True
				except requests.RequestException:
					continue
	return False