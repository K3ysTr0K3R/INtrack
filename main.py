#!/usr/bin/env python3

import sys
from rich.console import Console
import argparse
import random
import socket
import urllib3
import concurrent.futures
from alive_progress import alive_bar, config_handler
import subprocess
import threading
import os
from lib.worms.vscode_sftp_worm import crawl_vscode_sftp
from lib.worms.microsoft_worm import microsoft_worm
from lib.worms.tomcat_worm import exploit_CVE_2017_12615_CVE_2017_12617
from lib.worms.hadoop_worm import hadoop_worm

from lib.backdoors.antsword_backdoor import antsword_backdoor
from lib.backdoors.php_backdoor import php_backdoor
from lib.backdoors.mikrotik_backdoor import mikrotik_backdoor
from lib.backdoors.dlink_backdoor import dlink_backdoor
from lib.backdoors.cisco_backdoor import cisco_backdoor
from lib.backdoors.webshell_backdoor import webshell_backdoor

from lib.exposures.robots_scanner import check_robots
from lib.exposures.security_scanner import check_security
from lib.exposures.sitemap_scanner import check_sitemap
from lib.exposures.api_docs_scanner import check_api_docs
from lib.exposures.security_headers import check_security_headers
from lib.exposures.sensitive_endpoint_scanner import check_sensitive_endpoints
from lib.miscellaneous.dir_listing import check_dir_listing

from lib.iot.gargoyle_scanner import check_gargoyle
from lib.iot.gpon_scanner import check_gpon
from lib.iot.webcamxp_scanner import check_webcamxp
from lib.iot.netgear_scanner import scan_netgear
from lib.iot.hikvision_scanner import check_hikvision
from lib.iot.cisco_scanner import check_cisco
from lib.iot.epmp_scanner import check_epmp
from lib.iot.network_camera import check_network_camera
from lib.iot.routeros_scanner import mikrotik_router

from lib.instances.wordpress_scanner import check_wordpress
from lib.instances.microsoft_iis import check_microsoft_iis
from lib.instances.server_scanner import check_servers
from lib.instances.webmin_scanner import scan_webmin
from lib.instances.thinkphp import check_thinkphp
from lib.instances.weblogic_scanner import check_weblogic
from lib.instances.drupal import check_drupal
from lib.instances.ncast import check_ncast
from lib.instances.jira import check_jira
from lib.instances.joomla import check_joomla
from lib.instances.zimbra import check_zimbra
from lib.instances.apache import check_apache
from lib.instances.php import php
from lib.instances.webdav_scanner import check_webdav
from lib.instances.moveit import check_moveit
from lib.instances.nginx import check_nginx
from lib.network.telnet_scanner import scan_telnet
from lib.network.rdp_scanner import scan_rdp
from lib.network.rtsp_mangler import rtsp_checks
from lib.network.adb_misconfig import check_adb
from lib.network.port_scanner import port_scanner
from lib.network.network_handler import get_ips_from_subnet
from lib.instances.bigip_scanner import bigip

from lib.vulns.netgear.CVE_2016_6277 import check_CVE_2016_6277

from lib.vulns.ncast.CVE_2024_0305 import check_CVE_2024_0305

from lib.vulns.fortinet.CVE_2018_13379 import check_CVE_2018_13379

from lib.vulns.hikvision.CVE_2017_7921 import check_CVE_2017_7921

from lib.vulns.zabbix.CVE_2019_17382 import check_CVE_2019_17382

from lib.vulns.cisco.CVE_2019_1653 import check_CVE_2019_1653
from lib.vulns.cisco.CVE_2020_3452 import check_CVE_2020_3452
from lib.vulns.cisco.CVE_2021_1445 import check_CVE_2021_1445
from lib.vulns.cisco.CVE_2020_3259 import check_CVE_2020_3259
from lib.vulns.cisco.CVE_2019_2000 import check_CVE_2019_2000
from lib.vulns.cisco.CVE_2022_20842 import check_CVE_2022_20842

from lib.vulns.thinkphp.CVE_2022_47945 import check_CVE_2022_47945

from lib.vulns.hikvision.CVE_2021_36260 import check_CVE_2021_36260

from lib.vulns.wordpress.CVE_2017_5487 import check_CVE_2017_5487

from lib.vulns.fortinet.CVE_2022_40684 import check_CVE_2022_40684

from lib.vulns.joomla.CVE_2023_23752 import check_CVE_2023_23752

from lib.vulns.dahua.CVE_2017_7925 import check_CVE_2017_7925

from lib.vulns.microsoft.CVE_2017_7269 import check_CVE_2017_7269
from lib.vulns.microsoft.CVE_2015_1635 import check_CVE_2015_1635
from lib.vulns.microsoft.CVE_2021_38647 import check_CVE_2021_38647
from lib.vulns.microsoft.CVE_2021_34473 import check_CVE_2021_34473

from lib.vulns.f5bigip.CVE_2022_1388 import check_CVE_2022_1388
from lib.vulns.f5bigip.CVE_2021_22986 import check_CVE_2021_22986

from lib.workflows.microsoft_workflow import check_microsoft_workflow

from lib.color_handler import print_colour

from lib.hostname_handler import get_hostname

from lib.http_handler import http_https

console = Console()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_red(message):
    """Print a message in red color for errors"""
    print_colour(f"[-] {message}")

def ascii_art():
    print("")
    console.print("[bold bright_yellow]██╗███╗   ██╗████████╗██████╗  █████╗  ██████╗██╗  ██╗[/bold bright_yellow]")
    console.print("[bold bright_yellow]██║████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝[/bold bright_yellow]")
    console.print("[bold bright_yellow]██║██╔██╗ ██║   ██║   ██████╔╝███████║██║     █████╔╝[/bold bright_yellow]")
    console.print("[bold bright_yellow]██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗[/bold bright_yellow]")
    console.print("[bold bright_yellow]██║██║ ╚████║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗[/bold bright_yellow]")
    console.print("[bold bright_yellow]╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold bright_yellow]") 
    print("")
    print_colour("[!] Coded By: K3ysTr0K3R")

def is_reserved_ip(ip):
    """Check if an IP address is in a reserved range"""
    # Convert IP string to integer for easier comparison
    octets = list(map(int, ip.split('.')))
    ip_int = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
    
    # Reserved ranges to skip
    reserved_ranges = [
        (0x00000000, 0x00FFFFFF),    # 0.0.0.0/8 - Local Identification
        (0x0A000000, 0x0AFFFFFF),    # 10.0.0.0/8 - Private Network
        (0x64400000, 0x647FFFFF),    # 100.64.0.0/10 - Shared Address Space
        (0x7F000000, 0x7FFFFFFF),    # 127.0.0.0/8 - Loopback
        (0xA9FE0000, 0xA9FEFFFF),    # 169.254.0.0/16 - Link Local
        (0xAC100000, 0xAC1FFFFF),    # 172.16.0.0/12 - Private Network
        (0xC0000000, 0xC00000FF),    # 192.0.0.0/24 - IETF Protocol Assignments
        (0xC0000200, 0xC00002FF),    # 192.0.2.0/24 - TEST-NET-1
        (0xC0A80000, 0xC0A8FFFF),    # 192.168.0.0/16 - Private Network
        (0xC6120000, 0xC613FFFF),    # 198.18.0.0/15 - Network Interconnect
        (0xC6336400, 0xC63364FF),    # 198.51.100.0/24 - TEST-NET-2
        (0xCB007100, 0xCB0071FF),    # 203.0.113.0/24 - TEST-NET-3
        (0xE0000000, 0xEFFFFFFF),    # 224.0.0.0/4 - Multicast
        (0xF0000000, 0xFFFFFFFF),    # 240.0.0.0/4 - Reserved
    ]
    
    # Check if IP is in any reserved range
    for start, end in reserved_ranges:
        if start <= ip_int <= end:
            return True
    
    return False

def generate_weighted_octet():
    """Generate an octet with higher probability of common server IPs"""
    # Weighted distribution favoring common server IP patterns
    weights = [
        (1, 25, 0.2),    # Lower range less common
        (25, 100, 0.4),  # Mid-low range more common
        (100, 200, 0.3), # Mid-high range common
        (200, 255, 0.1)  # High range less common
    ]
    
    # Pick a range based on weights
    choice = random.random()
    cumulative = 0
    for start, end, weight in weights:
        cumulative += weight
        if choice <= cumulative:
            return random.randint(start, end)
    
    return random.randint(1, 254)  # Fallback

def generate_ip():
    """Generate a random public IP address, avoiding reserved ranges"""
    max_attempts = 10  # Limit attempts to avoid infinite loops
    
    for _ in range(max_attempts):
        # Generate random IP with weighted distribution
        ip = f"{generate_weighted_octet()}.{generate_weighted_octet()}.{generate_weighted_octet()}.{generate_weighted_octet()}"
        
        if not is_reserved_ip(ip):
            return ip
    
    # Fallback to a common range if we couldn't find a valid IP
    return f"{random.randint(50, 70)}.{random.randint(30, 150)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def check_port(ip, port, timeout=1.0):
    """Check if a port is open with proper timeout handling"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True
        except (socket.timeout, socket.error):
            return False
        except Exception as e:
            print_red(f"Unexpected error checking port {port} on {ip}: {e}")
            return False

def parse_ports(port_str):
    """Parse port string into a list of integer ports with improved error handling"""
    if not port_str:
        return [80]  # Default to port 80
    
    ports = set()
    try:
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        print_red(f"Invalid port range: {start}-{end}")
                        continue
                    if start < 1 or end > 65535:
                        print_red(f"Port range {start}-{end} outside valid range (1-65535)")
                        continue
                    ports.update(range(start, end + 1))
                except ValueError:
                    print_red(f"Invalid port range format: {part}")
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        print_red(f"Invalid port number: {port} (must be 1-65535)")
                except ValueError:
                    print_red(f"Invalid port number: {part}")
    except Exception as e:
        print_red(f"Error parsing ports: {e}")
        return [80]  # Fallback to port 80 on error
        
    if not ports:
        print_red("No valid ports specified, using default port 80")
        return [80]
        
    return sorted(ports)

def parse_comma_separated_args(arg_string):
    if not arg_string:
        return []
    return [arg.strip().lower() for arg in arg_string.split(",")]

def is_valid_ip(ip):
    """Validate IP address format"""
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        for octet in octets:
            num = int(octet)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

def process_ip(ip, args):
    """Process a single IP address with all enabled checks"""
    # Validate IP format first
    if not is_valid_ip(ip):
        print_red(f"Invalid IP address format: {ip}")
        return None
        
    ports = parse_ports(args.p)
    lhost = args.lh
    lport = args.lp

    if args.hostname:
        hostname = get_hostname(ip)
        if hostname and hostname != "None":
            print_colour(f"[+] Hostname resolved: {ip} -> {hostname}")

    if args.probe:
        probe_result = http_https(ip, args.timeout)
        if probe_result:
            url = f"{probe_result['protocol']}://{ip}"
            print(url)
            return url
        return None

    # Use the timeout from args for port checking
    port_timeout = min(args.timeout / 2, 3.0)  # Use half the HTTP timeout, max 3 seconds
    open_ports = [port for port in ports if check_port(ip, port, port_timeout)]
    if not open_ports:
        return None

    backdoor_checks = parse_comma_separated_args(args.backdoor)
    vuln_checks = parse_comma_separated_args(args.vuln)
    instance_checks = parse_comma_separated_args(args.instance)
    exposure_checks = parse_comma_separated_args(args.exposure)
    iot_checks = parse_comma_separated_args(args.iot)
    misc_checks = parse_comma_separated_args(args.miscellaneous)
    network_checks = parse_comma_separated_args(args.network)
    worms = parse_comma_separated_args(args.worm)

    for backdoor in backdoor_checks:
        for backdoor_name, check_function in [
            ('antsword', antsword_backdoor),
            ('php', php_backdoor),
            ('mikrotik', mikrotik_backdoor),
            ('dlink', dlink_backdoor),
            ('cisco', cisco_backdoor),
            ('webshell', webshell_backdoor)
        ]:
            if backdoor == backdoor_name and check_function(ip, open_ports, args.timeout):
                return ip

    for vuln in vuln_checks:
        for check_name, check_function in [
            ('CVE-2017-7921', check_CVE_2017_7921),
            ('CVE-2019-17382', check_CVE_2019_17382),
            ('CVE-2018-13379', check_CVE_2018_13379),
            ('CVE-2022-47945', check_CVE_2022_47945),
            ('CVE-2021-36260', check_CVE_2021_36260),
            ('CVE-2017-5487', check_CVE_2017_5487),
            ('CVE-2017-7925', check_CVE_2017_7925),
            ('CVE-2024-0305', check_CVE_2024_0305),
            ('CVE-2016-6277', check_CVE_2016_6277),
            ('CVE-2019-1653', check_CVE_2019_1653),
            ('CVE-2020-3452', check_CVE_2020_3452),
            ('CVE-2021-1445', check_CVE_2021_1445),
            ('CVE-2020-3259', check_CVE_2020_3259),
            ('CVE-2019-2000', check_CVE_2019_2000),
            ('CVE-2022-20842', check_CVE_2022_20842),
            ('CVE-2022-40684', check_CVE_2022_40684),
            ('CVE-2021-34473', check_CVE_2021_34473),
            ('CVE-2023-23752', check_CVE_2023_23752),
            ('CVE-2015-1635', check_CVE_2015_1635),
            ('CVE-2022-1388', check_CVE_2022_1388),
            ('CVE-2021-22986', check_CVE_2021_22986)
        ]:
            if vuln.upper() == check_name.upper() and check_function(ip, open_ports, args.timeout):
                return ip

    for instance in instance_checks:
        for instance_name, check_function in [
            ('wordpress', check_wordpress),
            ('microsoft', check_microsoft_iis),
            ('server', check_servers),
            ('webmin', scan_webmin),
            ('thinkphp', check_thinkphp),
            ('weblogic', check_weblogic),
            ('drupal', check_drupal),
            ('ncast', check_ncast),
            ('jira', check_jira),
            ('joomla', check_joomla),
            ('zimbra', check_zimbra),
            ('apache', check_apache),
            ('php', php),
            ('webdav', check_webdav),
            ('moveit', check_moveit),
            ('nginx', check_nginx),
            ('bigip', bigip)
        ]:
            if instance == instance_name and check_function(ip, open_ports, args.timeout):
                return ip

    for exposure in exposure_checks:
        for exposure_name, check_function in [
            ('robots-txt', check_robots),
            ('security-txt', check_security),
            ('sitemap', check_sitemap),
            ('api-docs', check_api_docs),
            ('security-headers', check_security_headers),
            ('sensitive-endpoints', check_sensitive_endpoints)
        ]:
            if exposure == exposure_name and check_function(ip, open_ports, args.timeout):
                return ip

    for iot in iot_checks:
        for iot_name, check_function in [
            ('gargoyle', check_gargoyle),
            ('gpon', check_gpon),
            ('webcamxp', check_webcamxp),
            ('netgear', scan_netgear),
            ('hikvision', check_hikvision),
            ('cisco', check_cisco),
            ('epmp', check_epmp),
            ('network-camera', check_network_camera),
            ('mikrotik', mikrotik_router)
        ]:
            if iot == iot_name and check_function(ip, open_ports, args.timeout):
                return ip

    for misc in misc_checks:
        for misc_name, check_function in [
            ('dir-listing', check_dir_listing)
        ]:
            if misc == misc_name and check_function(ip, open_ports, args.timeout):
                return ip

    for network in network_checks:
        for network_name, check_function in [
            ('telnet', scan_telnet),
            ('rtsp', rtsp_checks),
            ('adb-misconfig', check_adb),
            ('network', port_scanner)
        ]:
            if network == network_name and check_function(ip, open_ports):
                return ip

    if worms and lhost and lport:
        for worm in worms:
            for worm_name, worm_func in [
            ('vscode-sftp', crawl_vscode_sftp),
            ('microsoft', microsoft_worm),
            ('tomcat', exploit_CVE_2017_12615_CVE_2017_12617),
            ('hadoop', hadoop_worm)
            ]:
                if worm == worm_name:
                    for port in open_ports:
                        worm_func(ip, port, lhost, lport)
                return ip
    elif worms:
        print_red("Error: Both -lh (lhost) and -lp (lport) must be provided with -worm.")
        sys.exit(1)

    if open_ports and not any([args.instance, args.vuln, args.exposure, args.iot, args.miscellaneous, worms]):
        return ip

    return None

def safe_open_file(filename, mode):
    """Safely open a file with path traversal protection"""
    # Normalize path to prevent path traversal
    safe_path = os.path.normpath(filename)
    # Check for suspicious patterns
    if '..' in safe_path or safe_path.startswith('/'):
        print_red(f"Suspicious file path detected: {filename}")
        return None
    
    try:
        return open(safe_path, mode)
    except FileNotFoundError:
        print_red(f"File not found: {safe_path}")
        return None
    except PermissionError:
        print_red(f"Permission denied: {safe_path}")
        return None
    except Exception as e:
        print_red(f"Error opening file {safe_path}: {e}")
        return None

def read_targets_from_file(filename):
    """Read targets from file with validation and better error handling"""
    ips = []
    
    # Use safe file opening
    f = safe_open_file(filename, 'r')
    if not f:
        print_red(f"Could not open file: {filename}")
        sys.exit(1)
    
    try:
        line_number = 0
        for line in f:
            line_number += 1
            target = line.strip()
            if not target or target.startswith('#'):
                continue  # Skip empty lines and comments
            
            if '/' in target:  # Subnet
                try:
                    subnet_ips = get_ips_from_subnet(target)
                    ips.extend(subnet_ips)
                except Exception as e:
                    print_red(f"Error parsing subnet {target} on line {line_number}: {e}")
            else:  # Single IP
                if is_valid_ip(target):
                    ips.append(target)
                else:
                    print_red(f"Invalid IP format on line {line_number}: {target}")
    finally:
        f.close()
        
    if not ips:
        print_red(f"No valid IPs found in file '{filename}'.")
        sys.exit(1)
        
    return ips

def list_scanners():
    print_colour("[+] Available Scanners:")
    
    print_colour("[*] Worms:")
    print_colour("[!] - vscode-sftp")
    print_colour("[!] - microsoft")
    print_colour("[!] - tomcat")
    print_colour("[!] - hadoop")
    
    print_colour("[*] - Backdoors:")
    print_colour("[!] - antsword")
    
    print_colour("[*] Exposures:")
    print_colour("[!] - robots-txt")
    print_colour("[!] - security-txt")
    print_colour("[!] - sitemap")
    
    print_colour("[*] Instances:")
    print_colour("[!] - wordpress")
    print_colour("[!] - microsoft")
    print_colour("[!] - server")
    print_colour("[!] - webmin")
    print_colour("[!] - thinkphp")
    print_colour("[!] - weblogic")
    print_colour("[!] - drupal")
    print_colour("[!] - ncast")
    print_colour("[!] - jira")
    print_colour("[!] - joomla")
    print_colour("[!] - zimbra")
    print_colour("[!] - apache")
    print_colour("[!] - php")
    print_colour("[!] - webdav")
    print_colour("[!] - moveit")
    print_colour("[!] - nginx")
    print_colour("[!] - bigip")
    
    print_colour("[*] Network Checks:")
    print_colour("[!] - telnet")
    print_colour("[!] - rdp")
    print_colour("[!] - rtsp")
    print_colour("[!] - adb-misconfig")
    print_colour("[!] - port-scanner")
    
    print_colour("[*] IoT Checks:")
    print_colour("[!] - gargoyle")
    print_colour("[!] - gpon")
    print_colour("[!] - webcamxp")
    print_colour("[!] - netgear")
    print_colour("[!] - hikvision")
    print_colour("[!] - cisco")
    print_colour("[!] - epmp")
    print_colour("[!] - network-camera")
    print_colour("[!] - routeros")
    
    print_colour("[*] Miscellaneous Checks:")
    print_colour("[!] - dir-listing")
    
    print_colour("[*] Vulnerabilities:")
    print_colour("[!] - CVE-2016-6277")
    print_colour("[!] - CVE-2024-0305")
    print_colour("[!] - CVE-2018-13379")
    print_colour("[!] - CVE-2017-7921")
    print_colour("[!] - CVE-2019-17382")
    print_colour("[!] - CVE-2019-1653")
    print_colour("[!] - CVE-2022-47945")
    print_colour("[!] - CVE-2021-36260")
    print_colour("[!] - CVE-2017-5487")
    print_colour("[!] - CVE-2017-7925")
    print_colour("[!] - CVE-2022-40684")
    print_colour("[!] - CVE-2021-34473")
    print_colour("[!] - CVE-2023-23752")
    print_colour("[!] - CVE-2015-1635")
    print_colour("[!] - CVE-2022-1388")
    print_colour("[!] - CVE-2021-22986")
    print_colour("[!] - traversal")

    print_colour("[*] Workflow Scans:")
    print_colour("[!] - microsoft")

def main():
    ascii_art()
    
    # Configure global progress bar settings
    config_handler.set_global(
        spinner='dots_waves',
        force_tty=True,
        dual_line=True
    )
    
    parser = argparse.ArgumentParser(description="INtrack - Internet Crawler")
    parser.add_argument("-host", type=str, help="Specify a single target IP or subnet range of IPs to scan /24, /23, /22, etc.")
    parser.add_argument("-f", type=str, help="Specify a file containing target IPs.")
    parser.add_argument("-n", type=int, help="Number of targets to find. Can also be used to increase the range of the scan.")
    parser.add_argument("-p", type=str, default="80", help="Port(s) to check. Defaults to 80 if not provided.")
    parser.add_argument("-t", type=int, default=25, help="Number of threads to use.")
    parser.add_argument("-o", type=str, help="Store results into a file.")
    parser.add_argument("-lh", "-lhost", type=str, help="Add a listening host for revshells.")
    parser.add_argument("-lp", "-lport", type=str, help="A listening port for revshells.")
    parser.add_argument("-hostname", action="store_true", help="Resolve hostnames for IP addresses.")
    parser.add_argument("-instance", type=str, help="Type of instance to check.")
    parser.add_argument("-backdoor", type=str, help="Look for backdoor implants.")
    parser.add_argument("-worm", type=str, help="Enable special script execution with a specified type (e.g., 'vscode-sftp').")
    parser.add_argument("-vuln", type=str, help="Enable vuln script execution with a specified type (e.g., CVE-2017-7921).")
    parser.add_argument("-exposure", type=str, help="Used to detect exposure files.")
    parser.add_argument("-iot", type=str, help="Used to detect IoT devices.")
    parser.add_argument("-miscellaneous", type=str, help="Used for miscellaneous checks.")
    parser.add_argument("-workflows", type=str, help="Run workflow scans on your targets.")
    parser.add_argument("-network", type=str, help="Used for network scans.")
    parser.add_argument("-timeout", type=int, default=10, help="Timeout seconds for web requests.")
    parser.add_argument("-probe", action="store_true", help="Used for probing hosts for HTTP/HTTPS")
    parser.add_argument("-spider", type=str, help="Specify the subnet range to scan if a result is found (e.g., /20, /24).")
    parser.add_argument("-list", action="store_true", help="List available scanners and checks")
    parser.add_argument("-update", action="store_true", help="Update INtrack")
    parser.add_argument("-bar-style", type=str, default="smooth", choices=["smooth", "blocks", "bubbles", "solid", "classic", "brackets"], help="Progress bar style")

    args = parser.parse_args()

    def update_intrack():
        print_colour("[*] Checking for updates...")
        result = subprocess.run(["git", "pull"], capture_output=True, text=True)
        
        if result.returncode == 0:
            if "Already up to date" in result.stdout:
                print_colour("[*] INtrack is already up to date.")
            else:
                print_colour("[*] INtrack has been updated successfully.")
        else:
            print_colour("[*] Failed to update INtrack.")
            print_colour(f"[!] Error: {result.stderr}")

    if args.update:
        update_intrack()
        sys.exit(0)

    if args.list:
        list_scanners()
        sys.exit(0)

    found_targets = []

    if args.f:
        ip_addresses = read_targets_from_file(args.f)
        count = len(ip_addresses)
        print_colour(f"[*] Scanning {count} targets from file '{args.f}'")
    elif args.host:
        if "/" in args.host:
            ip_addresses = get_ips_from_subnet(args.host)
            count = len(ip_addresses)
            print_colour(f"[*] Scanning {count} targets from subnet '{args.host}'")
        else:
            ip_addresses = [args.host]
            count = 1
            print_colour(f"[*] Scanning 1 target: {args.host}")
    else:
        count = args.n or 0
        print_colour(f"[*] Scanning {count} random targets from the internet")

    # Print active scan details
    active_scans = []
    if args.backdoor: active_scans.append(f"Backdoor checks: {args.backdoor}")
    if args.vuln: active_scans.append(f"Vulnerability checks: {args.vuln}")
    if args.instance: active_scans.append(f"Instance checks: {args.instance}")
    if args.exposure: active_scans.append(f"Exposure checks: {args.exposure}")
    if args.iot: active_scans.append(f"IoT checks: {args.iot}")
    if args.miscellaneous: active_scans.append(f"Miscellaneous checks: {args.miscellaneous}")
    if args.network: active_scans.append(f"Network checks: {args.network}")
    if args.worm: active_scans.append(f"Worm checks: {args.worm}")
    
    if active_scans:
        print_colour("[*] Active scan modules:")
        for scan in active_scans:
            print_colour(f"    - {scan}")
    else:
        print_colour("[*] No specific scan modules activated - checking open ports only")
    
    print_colour(f"[*] Using {args.t} threads with {args.timeout}s timeout")
    if args.o:
        print_colour(f"[*] Results will be saved to: {args.o}")
    print_colour("----------------------------------------")

    # Use context manager for safe file handling
    output_file = None
    try:
        if args.o:
            output_file = safe_open_file(args.o, 'a')
            if not output_file:
                print_red(f"Unable to open output file '{args.o}'. Results will only be shown on screen.")

        # Implement IP generator for memory efficiency
        def generate_ip_batch(batch_size):
            """Memory-efficient generator for IP addresses"""
            for _ in range(batch_size):
                yield generate_ip()

        # Different progress bar handling for random scanning vs subnet/file scanning
        if not args.host and not args.f:
            # Create thread-safe counter
            counter_lock = threading.Lock()
            total_checked = 0
            found_count = 0
            
            # Random internet scanning - show progress based on IPs scanned
            total_to_scan = args.n * 20  # Estimate of IPs to scan to find targets
            with alive_bar(
                total_to_scan,  # Use estimated IPs to scan instead of target count
                title="Scanning Internet",
                enrich_print=False,
                bar=args.bar_style,
                stats=True,
                unit=" IPs"
            ) as progress_bar:
                
                def process_and_update(ip):
                    """Thread-safe wrapper for process_ip with counter updates"""
                    nonlocal total_checked, found_count
                    result = process_ip(ip, args)
                    
                    # Ensure thread-safe counter updates
                    with counter_lock:
                        total_checked += 1
                        # Update progress bar (only one thread at a time)
                        progress_bar.title(f"Scanning Internet [{total_checked}/{total_to_scan}] - Found {found_count}/{args.n}")
                        progress_bar()
                        
                        if result:
                            found_targets.append(result)
                            found_count += 1
                            # Thread-safe file write
                            if output_file:
                                with counter_lock:
                                    output_file.write(f"{result}\n")
                                    output_file.flush()
                    
                    return result
                
                while found_count < args.n:
                    batch_size = args.t * 10
                    # Use generator instead of list for memory efficiency
                    ip_addresses = generate_ip_batch(batch_size)
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                        batch_results = list(executor.map(process_and_update, ip_addresses))
                        
                        # Check if we've reached our target
                        if found_count >= args.n:
                            break
                
                # If we've scanned more than our estimate, increase it
                if total_checked >= total_to_scan:
                    with counter_lock:
                        old_total = total_to_scan
                        total_to_scan = int(total_to_scan * 1.5)  # Increase by 50%
                        progress_bar.total = total_to_scan
                        print_colour(f"[*] Increasing scan estimate: {old_total} → {total_to_scan} IPs")

                print("")  # Ensure we're on a new line
                print_colour(f"[+] Scan complete - Found {found_count}/{args.n} targets (Checked {total_checked} IPs)")
        else:
            # Create thread-safe counter for subnet/file scanning
            counter_lock = threading.Lock()
            ips_processed = 0
            found_count = 0
            
            # Subnet or file scanning - show progress based on IPs checked
            total_ips = len(ip_addresses)
            with alive_bar(
                total_ips,  # Use the actual IP count
                title="Scanning targets",
                enrich_print=False,
                bar=args.bar_style,
                stats=True,
                unit=" IPs"
            ) as progress_bar:
                
                def process_and_update_subnet(ip):
                    """Thread-safe wrapper for subnet/file scanning"""
                    nonlocal ips_processed, found_count
                    result = process_ip(ip, args)
                    
                    # Ensure thread-safe counter updates
                    with counter_lock:
                        ips_processed += 1
                        progress_bar.title(f"Scanning IPs [{ips_processed}/{total_ips}] - Found {found_count}")
                        progress_bar()
                        
                        if result:
                            found_targets.append(result)
                            found_count += 1
                            # Thread-safe file write
                            if output_file:
                                output_file.write(f"{result}\n")
                                output_file.flush()
                
                    return result
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                    # Process all IPs with thread-safe updates
                    batch_results = list(executor.map(process_and_update_subnet, ip_addresses))

                print("")  # Ensure we're on a new line
                print_colour(f"[+] Scan complete - Found {found_count} targets")

    finally:
        # Ensure file is closed properly
        if output_file:
            output_file.close()

    for targ in found_targets[:args.n]:
        print(targ)

if __name__ == "__main__":
    main()
