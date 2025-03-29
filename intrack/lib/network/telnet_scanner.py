import socket
from intrack.lib.color_handler import print_colour

def scan_telnet(ip, ports):
    success = False
    if isinstance(ports, list):
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((ip, port))
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore')
                    if banner.strip():
                        print_colour(f"{ip}:{port} [Banner: {banner.strip()}]")
                    else:
                        print_colour(f"{ip}:{port} [No banner]")
                except socket.timeout:
                    print_colour(f"{ip}:{port} [Connected, no response]")
                success = True
            except (socket.timeout, socket.error):
                continue
            finally:
                s.close()
    return success