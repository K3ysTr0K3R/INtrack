#!/usr/bin/env python3

import sys
import argparse
import random
import socket
import urllib3
import concurrent.futures
from alive_progress import alive_bar
from lib.network.network_handler import get_ips_from_subnet
from lib.instances.wordpress_scanner import check_wordpress
from lib.iot.gargoyle_scanner import check_gargoyle
from lib.iot.gpon_scanner import check_gpon
from lib.iot.webcamxp_scanner import check_webcamxp
from lib.worms.vscode_sftp_worm import crawl_vscode_sftp
from lib.vulns.CVE_2017_7921 import check_CVE_2017_7921
from lib.vulns.CVE_2019_17382 import check_CVE_2019_17382
from lib.instances.microsoft_iis import check_microsoft_iis
from lib.worms.microsoft_worm import microsoft_worm
from lib.instances.server_scanner import check_servers
from lib.network.telnet_scanner import scan_telnet
from lib.vulns.directory_traversal_scanner import traversal
from lib.network.rdp_scanner import scan_rdp
from lib.instances.webmin_scanner import scan_webmin
from lib.iot.netgear_scanner import scan_netgear
from lib.worms.tomcat_worm import exploit_CVE_2017_12615_CVE_2017_12617
from lib.exposures.robots_scanner import check_robots

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def log_result_background(target):
    with open('intrack.log', 'a') as log_file:
        log_file.write(f"{target}\n")

def generate_ip():
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))
            return True
        except (socket.timeout, socket.error):
            return False

def process_ip(ip, args):
    worm_checks = [
        ('vscode-sftp', crawl_vscode_sftp),
        ('microsoft', microsoft_worm),
        ('tomcat', lambda ip, port: exploit_CVE_2017_12615_CVE_2017_12617(ip, port))
    ]

    vuln_checks = [
        ('CVE-2017-7921', check_CVE_2017_7921),
        ('CVE-2019-17382', check_CVE_2019_17382),
        ('traversal', traversal)
    ]

    instance_checks = [
        ('wordpress', check_wordpress),
        ('gargoyle', check_gargoyle),
        ('gpon', check_gpon),
        ('webcamxp', check_webcamxp),
        ('microsoft', check_microsoft_iis),
        ('server', check_servers),
        ('webmin', scan_webmin),
        ('netgear', scan_netgear)
    ]

    exposure_checks = [
            ('robots-txt', check_robots)
    ]

    port_checks = [
        ('telnet', scan_telnet),
        ('rdp', scan_rdp)
    ]

    for worm, check_function in worm_checks:
        if args.worm == worm and check_function(ip, args.p):
            return ip

    for vuln, check_function in vuln_checks:
        if args.vuln == vuln and check_function(ip, args.p):
            return ip

    for instance, check_function in instance_checks:
        if args.instance == instance and check_function(ip, args.p):
            return ip

    for exposure, check_function in exposure_checks:
        if args.exposure == exposure and check_function(ip, args.p):
            return ip

    for port, check_function in port_checks:
        if args.port == port and check_function(ip, args.p):
            return ip

    if args.p is not None:
        if not args.instance and not args.vuln and check_port(ip, args.p):
            return ip
    else:
        print(f"Error: No port specified for IP {ip}. Please provide a port with the -p option.")
        sys.exit(1)

    return None

def read_targets_from_file(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="INtrack - Internet Crawler")
    parser.add_argument("-host", type=str, help="Specify a single target IP.")
    parser.add_argument("-f", type=str, help="Specify a file containing target IPs.")
    parser.add_argument("-n", type=int, help="Number of targets to find. Can also be used to increase the range of the scan.")
    parser.add_argument("-p", type=int, default=80, help="Port to check. Defaults to 80 if not provided.")
    parser.add_argument("-t", type=int, default=1, help="Number of threads to use.")
    parser.add_argument("-o", type=str, help="Store results into a file.")
    parser.add_argument("-instance", type=str, help="Type of instance to check (e.g., 'wordpress', 'gargoyle', 'gpon').")
    parser.add_argument("-worm", type=str, help="Enable special script execution with a specified type (e.g., 'vscode-sftp').")
    parser.add_argument("-vuln", type=str, help="Enable vuln script execution with a specified type (e.g., CVE-2017-7921).")
    parser.add_argument("-exposure", type=str, help="Used to detect exposure files.")
    parser.add_argument("-port", type=str, help="Used for port scans")

    args = parser.parse_args()

    found_targets = []

    if args.host:
        if "/" in args.host:
            ip_addresses = get_ips_from_subnet(args.host)
        else:
            ip_addresses = [args.host]
    elif args.f:
        ip_addresses = read_targets_from_file(args.f)
    else:
        if args.n is None or args.p is None:
            print("Error: You must provide both -n (number of targets) and -p (port) for internet scanning.")
            sys.exit(1)

    with alive_bar(args.n or len(ip_addresses), title="[Scanning Internet]", enrich_print=False, bar="blocks") as instance_bar:
        if not args.host and not args.f:
            while len(found_targets) < args.n:
                ip_addresses = [generate_ip() for _ in range(args.t * 10)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                    for result in executor.map(lambda ip: process_ip(ip, args), ip_addresses):
                        if result:
                            found_targets.append(result)
                            log_result_background(result)
                        instance_bar()

                if args.o:
                    with open(args.o, 'a') as file:
                        for target in found_targets:
                            file.write(f"{target}\n")

        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                for result in executor.map(lambda ip: process_ip(ip, args), ip_addresses):
                    if result:
                        found_targets.append(result)
                        log_result_background(result)
                    instance_bar()

            if args.o:
                with open(args.o, 'a') as file:
                    for target in found_targets:
                        file.write(f"{target}\n")

    for targ in found_targets[:args.n]:
        print(targ)

if __name__ == "__main__":
    main()
