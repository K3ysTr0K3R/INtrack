import socket
from lib.color_handler import print_colour

def port_scanner(ip, ports=None):
    if ports is None:
        ports = range(1, 65536)

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print_colour(f"[+] {ip}:{port}")
        except socket.error as err:
            continue
        finally:
            sock.close()