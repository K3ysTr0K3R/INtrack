import random
import string
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def generate_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_thinkphp(ip, ports=None, timeout=5):
	headers = {
	'User-Agent': user_agents()
	}
	paths = ["", "/", f"/?s={generate_string()}&c={generate_string()}&a={generate_string()}&m={generate_string()}"]
	matchers = [      
	'/Library/Think/',
	'{ Fast & Simple OOP PHP Framework } -- [ WE CAN DO IT JUST THINK ]',
	'/thinkphp/library/think/'
	]
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
					response = requests.get(url, headers=headers, verify=False, timeout=timeout)
					if any(matcher in response.text for matcher in matchers):
						print_colour(f"ThinkPHP detected: {url}")
						return True
				except requests.RequestException:
					continue
	return False