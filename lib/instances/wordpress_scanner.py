#import requests
#from lib.headers.headers_handler import user_agents
#from lib.color_handler import print_colour

#matchers = ["WordPress</title>", "/wp-login.php?action=lostpassword"]

#def check_wordpress(ip, ports=None, timeout=5):
 #   protocols = ["http", "https"]

 #   if ports is None:
 #       ports = [80]
 #   else:
  #      ports = [f":{port}" for port in ports]

 #   for protocol in protocols:
 #       for port in ports:
 #           url = f"{protocol}://{ip}{port}/wp-login.php"
 #           headers = {
 #               'User-Agent': user_agents()
 #           }
 #           try:
 #               response = requests.get(url, headers=headers, timeout=timeout, verify=False)
 #               if any(matcher in response.text for matcher in matchers):
 #                   print_colour(f"[+] Found WordPress site: {url}")
 #                   return True
 #           except requests.RequestException:
 #               continue
#    return False

import socket
import ssl
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

matchers = ["WordPress</title>", "/wp-login.php?action=lostpassword"]

def send_request(ip, port, use_ssl, timeout):
    """
    Sends an HTTP GET request using raw sockets and returns the response.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)

        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)

        request = f"GET /wp-login.php HTTP/1.1\r\n"
        request += f"Host: {ip}\r\n"
        request += f"User-Agent: {user_agents()}\r\n"
        request += "Connection: close\r\n\r\n"

        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        return response.decode(errors="ignore")  # Decode with error handling for non-UTF-8 data

    except (socket.timeout, socket.error, ssl.SSLError) as e:
        return None

def check_wordpress(ip, ports=None, timeout=5):
    protocols = [("http", 80, False), ("https", 443, True)]

    if ports:
        ports = [(None, port, False) for port in ports]  # Custom ports, assume HTTP

    for protocol, port, use_ssl in (protocols + (ports or [])):
        response = send_request(ip, port, use_ssl, timeout)

        if response and any(matcher in response for matcher in matchers):
            print_colour(f"[+] Found WordPress site: {protocol}://{ip}:{port}")
            return True

    return False
