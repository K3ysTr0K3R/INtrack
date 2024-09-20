import socket
from concurrent.futures import ThreadPoolExecutor
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def scan_rdp(ip, port=None, timeout=10):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            print_green(f"{ip}:{port}")
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception:
        return False
