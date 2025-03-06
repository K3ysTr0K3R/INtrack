import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def check_webdav(ip, ports=None, timeout=5):
	headers = {"User-Agent": user_agents()}
	webdav_methods = {'PROPFIND', 'MKCOL', 'MOVE', 'COPY'}
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]

	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}"
			try:
				response = requests.options(url, timeout=timeout, verify=False, headers=headers)
				allowed_methods = response.headers.get('Allow', '')
				if any(method in allowed_methods for method in webdav_methods):
					print_colour(f"[+] {url} - WebDAV detected on target")
					return True
			except requests.RequestException:
				continue
	return False
