import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_microsoft_iis(ip, ports=None, timeout=5):
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            try:
                url = f"{protocol}://{ip}{port}"
                headers = {
                    'User-Agent': user_agents()
                }
                response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
                server = response.headers.get('Server', '')
                if "IIS" in server:
                    print_colour(f"[+] {url} [{server}]")
                    return True
            except requests.RequestException:
                continue
    return False

#import socket
#import ssl
#from intrack.lib.headers.headers_handler import user_agents
#from intrack.lib.color_handler import print_colour

#def send_request(ip, port, use_ssl, timeout):
    """
    Sends an HTTP GET request using raw sockets and returns the response headers.
    """
#    try:
#        sock = socket.create_connection((ip, port), timeout=timeout)
        
#        if use_ssl:
#            context = ssl.create_default_context()
#            sock = context.wrap_socket(sock, server_hostname=ip)

#        request = f"GET / HTTP/1.1\r\n"
#        request += f"Host: {ip}\r\n"
#        request += f"User-Agent: {user_agents()}\r\n"
#        request += "Connection: close\r\n\r\n"
        
#        sock.sendall(request.encode())

#        response = b""
#        while True:
#            chunk = sock.recv(4096)
#            if not chunk:
#                break
#            response += chunk

#        sock.close()

        # Extract headers only (response before the first empty line)
#        headers = response.split(b"\r\n\r\n")[0].decode(errors="ignore")
#        return headers

#    except (socket.timeout, socket.error, ssl.SSLError):
#        return None

#def check_microsoft_iis(ip, ports=None, timeout=5):
 #   protocols = [("http", 80, False), ("https", 443, True)]

 #   if ports:
 #       ports = [(None, port, False) for port in ports]  # Custom ports, assume HTTP

#    for protocol, port, use_ssl in (protocols + (ports or [])):
#        headers = send_request(ip, port, use_ssl, timeout)

#        if headers:
#            for line in headers.split("\r\n"):
#                if line.lower().startswith("server:"):
#                    server_banner = line.split(":", 1)[1].strip()
#                    if "IIS" in server_banner:
#                        print_colour(f"[+] {protocol}://{ip}:{port} [{server_banner}]")
#                        return True

#    return False