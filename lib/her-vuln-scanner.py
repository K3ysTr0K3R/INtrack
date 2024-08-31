import sys
from scapy.all import *
import paramiko
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        # TCP SYN scan using Scapy
        syn = IP(dst=ip)/TCP(dport=port, flags="S")
        syn_ack = sr1(syn, timeout=1, verbose=0)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == "SA":
            return port, "open"
        else:
            return port, "closed"
    except:
        return port, "error"

def check_ssh(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except:
        return False

def scan_target(ip, ports, ssh_creds):
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        port_results = list(executor.map(lambda p: scan_port(ip, p), ports))
    
    for port, status in port_results:
        if status == "open":
            service = "Unknown"
            if port == 22:
                service = "SSH"
                if ssh_creds:
                    ssh_success = check_ssh(ip, port, ssh_creds[0], ssh_creds[1])
                    if ssh_success:
                        service += " (Weak credentials!)"
            elif port == 80 or port == 443:
                service = "HTTP/HTTPS"
            results.append((port, status, service))
    
    return results

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ip> [ssh_username] [ssh_password]")
        sys.exit(1)

    target_ip = sys.argv[1]
    ssh_creds = None
    if len(sys.argv) == 4:
        ssh_creds = (sys.argv[2], sys.argv[3])

    target_ports = range(1, 1025)  # Scan first 1024 ports

    print(f"Scanning target {target_ip}")
    scan_results = scan_target(target_ip, target_ports, ssh_creds)

    if scan_results:
        print("Scan results:")
        for port, status, service in scan_results:
            print(f"  Port {port}: {status} - {service}")
    else:
        print("No open ports found")

if __name__ == "__main__":
    main()
