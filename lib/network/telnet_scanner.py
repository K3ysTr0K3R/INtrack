import socket
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def scan_telnet(ip, port=23):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((ip, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        if banner:
            print_green(f"{ip}:{port} [{banner}]")
            return True
        elif not banner:
            print_green(f"{ip}:{port}")
            return False
    except socket.timeout:
        return False
    except socket.error:
        return False
    finally:
        s.close()