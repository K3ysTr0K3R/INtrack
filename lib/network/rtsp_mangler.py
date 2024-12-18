import socket
import requests
from lib.color_handler import print_colour

rtsp_probe_packet = bytes.fromhex(
    "4f5054494f4e53207369703a6e6d205349502f322e300d0a5669613a205349502f322e302f544350206e6d3b6272616e63683d666f6f0d0a"
    "46726f6d3a203c7369703a6e6d406e6d3e3b7461673d726f6f740d0a546f3a203c7369703a6e6d32406e6d323e0d0a43616c6c2d49443a20"
    "35303030300d0a435365713a203432204f5054494f4e530d0a4d61782d466f7277617264733a2037300d0a436f6e74656e742d4c656e6774"
    "683a20300d0a436f6e746163743a203c7369703a6e6d406e6d3e0d0a4163636570743a206170706c69636174696f6e2f7364700d0a0d0a"
)

def rtsp_checks(ip, ports):
    if ports is None:
        ports = [554]
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.sendall(rtsp_probe_packet)
                response = sock.recv(1024).decode(errors="ignore")
                if "RTSP" in response:
                    print_colour(f"[+] RTSP confirmed on {ip} (port 554): {response.splitlines()[0]}")
                    for port in [80, 443]:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as web_sock:
                                web_sock.settimeout(5)
                                web_sock.connect((ip, port))
                                protocol = "HTTPS" if port == 443 else "HTTP"
                                url = f"{protocol.lower()}://{ip}"
                                req = requests.get(url)
                                server = req.headers.get('Server', '')
                                resp_code = req.status_code
                                if server:
                                    print_colour(f"[+] {protocol} (port {port}) found open on {ip} [{server}] [{resp_code}]")
                                else:
                                    print_colour(f"[+] {protocol} (port {port}) found open on {ip} [{resp_code}]")
                        except socket.error:
                            pass
        except socket.error:
            pass