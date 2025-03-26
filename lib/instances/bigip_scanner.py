import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def bigip(ip, ports=None, timeout=5):
	headers = {"User-Agent": user_agents()}
	protocols = ["http", "https"]
	if ports is None:
		ports = [80, 443, 8443]  # Common F5 ports
	else:
		ports = [f"{port}" for port in ports]

	for port in ports:
		for protocol in protocols:
			url = f"{protocol}://{ip}:{port}"
			try:
				response = requests.get(url, timeout=timeout, verify=False, headers=headers)
				
				# Check server header
				server = response.headers.get('Server', '')
				if "BigIP" in server or "BIG-IP" in server:
					print_colour(f"[+] {url} - F5 BigIP detected (Server header)")
					return True
				
				# Check for F5 specific cookies
				cookies = response.cookies
				for cookie in cookies:
					if any(x in cookie.name.lower() for x in ['bigip', 'big-ip', 'f5']):
						print_colour(f"[+] {url} - F5 BigIP detected (Cookie: {cookie.name})")
						return True
				
				# Check for login page signatures
				if "BIG-IP" in response.text or "/tmui/login.jsp" in response.text:
					print_colour(f"[+] {url} - F5 BigIP detected (Login page)")
					return True
				
				# Check for other known BigIP paths
				check_paths = [
					"/tmui/login.jsp",
					"/tmui/",
					"/mgmt/tm/sys",
					"/mgmt/shared/authn/login"
				]
				
				for path in check_paths:
					try:
						path_url = f"{url}{path}"
						path_response = requests.get(path_url, timeout=timeout, verify=False, headers=headers)
						if path_response.status_code == 200:
							# Found one of the BigIP-specific paths
							if "BIG-IP" in path_response.text or "F5 Networks" in path_response.text:
								print_colour(f"[+] {path_url} - F5 BigIP detected (Path signature)")
								return True
					except requests.RequestException:
						continue
				
			except requests.RequestException:
				continue
	return False