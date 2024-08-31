#!/usr/bin/env python3

import sys
import argparse
import random
import socket
import urllib3
import concurrent.futures
from alive_progress import alive_bar
from lib.wordpress_scanner import check_wordpress
from lib.gargoyle_scanner import check_gargoyle
from lib.gpon_scanner import check_gpon
from lib.webcamxp_scanner import check_webcamxp
from lib.vscode_sftp_worm import crawl_vscode_sftp
from lib.CVE_2017_7921 import check_CVE_2017_7921

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
        ('vscode-sftp', crawl_vscode_sftp)
    ]

    vuln_checks = [
        ('CVE-2017-7921', check_CVE_2017_7921)
    ]

    instance_checks = [
        ('wordpress', check_wordpress),
        ('gargoyle', check_gargoyle),
        ('gpon', check_gpon),
        ('webcamxp', check_webcamxp)
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

    if not args.instance and not args.vuln and check_port(ip, args.p):
        return ip

    return None

def main():
    parser = argparse.ArgumentParser(description="INtrack - Internet Crawler")
    parser.add_argument("-n", type=int, required=True, help="Number of targets to find.")
    parser.add_argument("-p", type=int, default=None, help="Port to check.")
    parser.add_argument("-t", type=int, default=1, help="Number of threads to use.")
    parser.add_argument("-o", type=str, help="Store results into a file.")
    parser.add_argument("-instance", type=str, help="Type of instance to check (e.g., 'wordpress', 'gargoyle', 'gpon').")
    parser.add_argument("-worm", type=str, help="Enable special script execution with a specified type (e.g., 'vscode-sftp').")
    parser.add_argument("-vuln", type=str, help="Enable vuln script execution with a specified type (e.g., CVE-2017-7921)")

    args = parser.parse_args()

    found_targets = []

    with alive_bar(None, title="[Scanning Internet]", enrich_print=False) as instance_bar:
        while len(found_targets) < args.n:
            ip_addresses = [generate_ip() for _ in range(args.t * 10)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                results = list(executor.map(lambda ip: process_ip(ip, args), ip_addresses))

            new_targets = list(filter(None, results))
            found_targets.extend(new_targets)

            for target in new_targets:
                log_result_background(target)

            if args.o:
                with open(args.o, 'a') as file:
                    for target in new_targets:
                        file.write(f"{target}\n")

            instance_bar(len(ip_addresses))

    print(f"\n[*] Total targets found: {len(found_targets)}\n")
    for targ in found_targets[:args.n]:
        print(targ)

if __name__ == "__main__":
    main()
