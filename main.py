#!/usr/bin/env python3

import sys
from rich.console import Console
import argparse
import random
import socket
import urllib3
import concurrent.futures
from alive_progress import alive_bar
import subprocess
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

from lib.vulns.netgear.CVE_2016_6277 import check_CVE_2016_6277

from lib.vulns.ncast.CVE_2024_0305 import check_CVE_2024_0305

from lib.vulns.fortinet.CVE_2018_13379 import check_CVE_2018_13379

from lib.vulns.hikvision.CVE_2017_7921 import check_CVE_2017_7921

from lib.vulns.zabbix.CVE_2019_17382 import check_CVE_2019_17382

from lib.vulns.cisco.CVE_2019_1653 import check_CVE_2019_1653

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

from lib.workflows.microsoft_workflow import check_microsoft_workflow

from lib.color_handler import print_colour

from lib.hostname_handler import get_hostname

from lib.http_handler import http_https

console = Console()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def parse_comma_separated_args(arg_string):
    if not arg_string:
        return []
    return [arg.strip().lower() for arg in arg_string.split(",")]

def process_ip(ip, args):
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

    open_ports = [port for port in ports if check_port(ip, port)]
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
            ('CVE-2022-40684', check_CVE_2022_40684),
            ('CVE-2021-34473', check_CVE_2021_34473),
            ('CVE-2023-23752', check_CVE_2023_23752),
            ('CVE-2015-1635', check_CVE_2015_1635)
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
            ('nginx', check_nginx)
        ]:
            if instance == instance_name and check_function(ip, open_ports, args.timeout):
                return ip

    for exposure in exposure_checks:
        for exposure_name, check_function in [
            ('robots-txt', check_robots),
            ('security-txt', check_security),
            ('sitemap', check_sitemap),
            ('api-docs', check_api_docs),
            ('security-headers', check_security_headers)
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
    print_colour("[!] - CVE-2024-10914")
    print_colour("[!] - traversal")

    print_colour("[*] Workflow Scans:")
    print_colour("[!] - microsoft")

def main():
    ascii_art()
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

    output_file = open(args.o, 'a') if args.o else None

    with alive_bar(args.n or len(ip_addresses), title="[Scanning Internet]", enrich_print=False, bar="blocks") as instance_bar:
        if not args.host and not args.f:
            while len(found_targets) < args.n:
                ip_addresses = [generate_ip() for _ in range(args.t * 10)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                    for result in executor.map(lambda ip: process_ip(ip, args), ip_addresses):
                        if result:
                            found_targets.append(result)
                            if output_file:
                                output_file.write(f"{result}\n")
                                output_file.flush()
                        instance_bar()
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.t) as executor:
                for result in executor.map(lambda ip: process_ip(ip, args), ip_addresses):
                    if result:
                        found_targets.append(result)
                        if output_file:
                            output_file.write(f"{result}\n")
                            output_file.flush()
                    instance_bar()

    if output_file:
        output_file.close()

    for targ in found_targets[:args.n]:
        print(targ)

if __name__ == "__main__":
    main()
