import socket
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

def mikrotik_backdoor(ip, ports=None, timeout=10):
    if ports is None:
        ports = [8291, 8728, 8729]
    else:
        ports = ports
    
    for port in ports:
        try:
            # Test for CVE-2018-14847
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            test_packet = b'\x03\x00\x00\x00\x01\x00\x00\x00\x88\x22\x00\x00\x00\x01\x00\x00\x00'
            sock.send(test_packet)
            
            response = sock.recv(1024)
            if b'\x88\x22\x00\x00' in response:
                print_colour(f"[+] Mikrotik RouterOS backdoor detected: {ip}:{port}")
                return True
            sock.close()
        except (socket.error, socket.timeout):
            continue
    return False