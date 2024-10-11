import re
import socket
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def check_adb(ip, ports=None):
    if ports is None:
        ports = [5555]
    else:
        ports = [port for port in ports]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.send(b"\x43\x4e\x58\x4e\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1\x68\x6f\x73\x74\x3a\x3a\x00")
            data = sock.recv(2048)
            data = data.decode('utf-8', 'ignore')
            product_name = re.search(r"product.name=(.*?);", data)
            product_model = re.search(r"ro.product.model=(.*?);", data)
            product_device = re.search(r"ro.product.device=(.*?);", data)
            if product_name or product_model or product_device:
                print_green(f"Android Debug Bridge: {ip}:{port} [Product Name: {product_name.group(1) if product_name else 'N/A'}] [Product Model: {product_model.group(1) if product_model else 'N/A'}] [Product Device: {product_device.group(1) if product_device else 'N/A'}]")
                return True
        except Exception:
            return False
        finally:
            sock.close()
    return False