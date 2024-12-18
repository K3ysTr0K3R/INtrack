import string
import random
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def generate_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_weblogic(ip, ports=None, timeout=10):
	headers = {
	"User-Agent": user_agents()
	}
	path = f"/{generate_string()}"
	matchers = ["From RFC 2068", "Error 404--Not Found"]
	protocols = ["http", "https"]
	if ports is None:
		ports = [80]
	else:
		ports = [f":{port}" for port in ports]
	for protocol in protocols:
		for port in ports:
			url = f"{protocol}://{ip}{port}{path}"
			try:
				response = requests.get(url, verify=False, timeout=timeout, headers=headers)
				if any(matcher in response.text for matcher in matchers):
					print_colour(f"[+] WebLogic detected: {url}")
					return True
			except requests.RequestException:
				continue
	return False