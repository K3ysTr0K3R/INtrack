#!/usr/bin/env python3

import os
import sys
import random
import socket
import urllib3
import threading
import concurrent.futures
import rich_click as click

from bisect import bisect
from itertools import accumulate
from rich.console import Console
from alive_progress import alive_bar, config_handler

from intrack.lib.worms import *
from intrack.lib.backdoors import *
from intrack.lib.exposures import *
from intrack.lib.miscellaneous import *
from intrack.lib.iot import *
from intrack.lib.instances import *
from intrack.lib.network import *
from intrack.lib.vulns import *
from intrack.lib.workflows import *
from intrack.lib.color_handler import print_colour
from intrack.lib.hostname_handler import get_hostname
from intrack.lib.http_handler import http_https

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
    return any(start <= ip_int <= end for start, end in reserved_ranges)

def generate_weighted_octet():
    weights = [(1, 25, 0.2), (25, 100, 0.4), (100, 200, 0.3), (200, 255, 0.1)]
    cumulative_weights = list(accumulate(weight for _, _, weight in weights))
    choice = random.random()
    index = bisect(cumulative_weights, choice)
    start, end, _ = weights[index] if index < len(weights) else (1, 254, 1.0)
    return random.randint(start, end)

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
    """Parse port string inline with error logging, minimal branching, and validation."""
    if not port_str:
        return [80]

    ports = set()

    [ports.update(range(start, end + 1)) if (start := int(part.split('-')[0])) <= (end := int(part.split('-')[1])) <= 65535 and start >= 1
     else print_red(f"Ignored invalid range: {part}")
     for part in map(str.strip, port_str.split(','))
     if '-' in part and part.count('-') == 1 and all(p.isdigit() for p in part.split('-'))]

    [ports.add(port) if 1 <= (port := int(part)) <= 65535
     else print_red(f"Ignored invalid port: {port}")
     for part in map(str.strip, port_str.split(','))
     if '-' not in part and part.isdigit()]

    if not ports:
        print_red("No valid ports found, using default port 80")
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

def process_ip(ip, kwargs):
    """Process a single IP address with all enabled checks"""
    if not is_valid_ip(ip):
        print_red(f"Invalid IP address format: {ip}")
        return None

    ports = parse_ports(kwargs["port"])
    lhost = kwargs["lhost"]
    lport = kwargs["lport"]

    if kwargs["hostname"]:
        hostname = get_hostname(ip)
        if hostname and hostname != "None":
            print_colour(f"[+] Hostname resolved: {ip} -> {hostname}")

    if kwargs["probe"]:
        probe_result = http_https(ip, kwargs["timeout"])
        if probe_result:
            url = f"{probe_result['protocol']}://{ip}"
            print(url)
            return url
        return None

    port_timeout = min(kwargs["timeout"] / 2, 3.0)
    open_ports = [port for port in ports if check_port(ip, port, port_timeout)]
    if not open_ports:
        return None

    backdoor_checks = parse_comma_separated_args(kwargs["backdoor"])
    vuln_checks = parse_comma_separated_args(kwargs["vuln"])
    instance_checks = parse_comma_separated_args(kwargs["instance"])
    exposure_checks = parse_comma_separated_args(kwargs["exposure"])
    iot_checks = parse_comma_separated_args(kwargs["iot"])
    misc_checks = parse_comma_separated_args(kwargs["miscellaneous"])
    network_checks = parse_comma_separated_args(kwargs["network"])
    worms = parse_comma_separated_args(kwargs["worm"])

    def run_checks(checks, mapping, timeout=True):
        for item in checks:
            for name, func in mapping:
                if item == name and func(ip, open_ports, kwargs["timeout"] if timeout else None):
                    return ip
        return None

    if res := run_checks(backdoor_checks, [
        ("antsword", antsword_backdoor), ("php", php_backdoor), ("mikrotik", mikrotik_backdoor),
        ("dlink", dlink_backdoor), ("cisco", cisco_backdoor), ("webshell", webshell_backdoor)
    ]): return res

    if res := run_checks(vuln_checks, [
        ("CVE-2017-7921", check_CVE_2017_7921), ("CVE-2019-17382", check_CVE_2019_17382),
        ("CVE-2018-13379", check_CVE_2018_13379), ("CVE-2022-47945", check_CVE_2022_47945),
        ("CVE-2021-36260", check_CVE_2021_36260), ("CVE-2017-5487", check_CVE_2017_5487),
        ("CVE-2017-7925", check_CVE_2017_7925), ("CVE-2024-0305", check_CVE_2024_0305),
        ("CVE-2016-6277", check_CVE_2016_6277), ("CVE-2019-1653", check_CVE_2019_1653),
        ("CVE-2020-3452", check_CVE_2020_3452), ("CVE-2021-1445", check_CVE_2021_1445),
        ("CVE-2020-3259", check_CVE_2020_3259), ("CVE-2019-2000", check_CVE_2019_2000),
        ("CVE-2022-20842", check_CVE_2022_20842), ("CVE-2022-40684", check_CVE_2022_40684),
        ("CVE-2021-34473", check_CVE_2021_34473), ("CVE-2023-23752", check_CVE_2023_23752),
        ("CVE-2015-1635", check_CVE_2015_1635), ("CVE-2022-1388", check_CVE_2022_1388),
        ("CVE-2021-22986", check_CVE_2021_22986)
    ]): return res

    if res := run_checks(instance_checks, [
        ("wordpress", check_wordpress), ("microsoft", check_microsoft_iis), ("server", check_servers),
        ("webmin", scan_webmin), ("thinkphp", check_thinkphp), ("weblogic", check_weblogic),
        ("drupal", check_drupal), ("ncast", check_ncast), ("jira", check_jira),
        ("joomla", check_joomla), ("zimbra", check_zimbra), ("apache", check_apache),
        ("php", php), ("webdav", check_webdav), ("moveit", check_moveit),
        ("nginx", check_nginx), ("bigip", bigip)
    ]): return res

    if res := run_checks(exposure_checks, [
        ("robots-txt", check_robots), ("security-txt", check_security), ("sitemap", check_sitemap),
        ("api-docs", check_api_docs), ("security-headers", check_security_headers),
        ("sensitive-endpoints", check_sensitive_endpoints)
    ]): return res

    if res := run_checks(iot_checks, [
        ("gargoyle", check_gargoyle), ("gpon", check_gpon), ("webcamxp", check_webcamxp),
        ("netgear", scan_netgear), ("hikvision", check_hikvision), ("cisco", check_cisco),
        ("epmp", check_epmp), ("network-camera", check_network_camera), ("mikrotik", mikrotik_router)
    ]): return res

    if res := run_checks(misc_checks, [
        ("dir-listing", check_dir_listing)
    ]): return res

    for network in network_checks:
        for name, func in [("telnet", scan_telnet), ("rtsp", rtsp_checks), ("adb-misconfig", check_adb), ("network", port_scanner)]:
            if network == name and func(ip, open_ports):
                return ip

    if worms and lhost and lport:
        for worm in worms:
            for name, func in [
                ("vscode-sftp", crawl_vscode_sftp), ("microsoft", microsoft_worm),
                ("tomcat", exploit_CVE_2017_12615_CVE_2017_12617), ("hadoop", hadoop_worm)
            ]:
                if worm == name:
                    for port in open_ports:
                        func(ip, port, lhost, lport)
                    return ip
    elif worms:
        print_red("Error: Both -lh (lhost) and -lp (lport) must be provided with -worm.")
        sys.exit(1)

    if open_ports and not any([kwargs["instance"], kwargs["vuln"], kwargs["exposure"], kwargs["iot"], kwargs["miscellaneous"], worms]):
        return ip

    return None

def safe_open_file(filename, mode):
    """Safely open a file with path traversal protection."""
    safe_path = os.path.normpath(filename)

    # Check for suspicious patterns like '..' or starting from root
    if '..' in safe_path or safe_path.startswith(os.sep):
        print_red(f"Suspicious file path detected: {filename}")
        return None

    try:
        return open(safe_path, mode)
    except (FileNotFoundError, PermissionError) as e:
        print_red(f"{e.strerror}: {safe_path}")
    except Exception as e:
        print_red(f"Error opening file {safe_path}: {e}")
    return None

def read_targets_from_file(filename):
    """Read targets from file with validation and better error handling"""
    # Use safe file opening
    f = safe_open_file(filename, 'r')
    if not f:
        print_red(f"Could not open file: {filename}")
        sys.exit(1)
    
    ips = []

    def process_line(line, line_number):
        target = line.strip()

        # Skip empty lines and comments
        if not target or target.startswith('#'):
            return

        # Process subnet
        if '/' in target:
            try:
                subnet_ips = get_ips_from_subnet(target)
                ips.extend(subnet_ips)
            except Exception as e:
                print_red(f"Error parsing subnet {target} on line {line_number}: {e}")
            return

        # Process single IP
        if is_valid_ip(target):
            ips.append(target)
            return

        # Invalid IP format
        print_red(f"Invalid IP format on line {line_number}: {target}")

    try:
        for line_number, line in enumerate(f, 1):  # Start line number at 1
            process_line(line, line_number)
    finally:
        f.close()

    # Ensure there are valid IPs
    if not ips:
        print_red(f"No valid IPs found in file '{filename}'.")
        sys.exit(1)

    return ips

def list_scanners():
    print_colour("[+] Available Scanners:\n")

    print()
    print_colour("[*] Worms:")
    for worm in ["vscode-sftp", "microsoft", "tomcat", "hadoop"]:
        print_colour(f"[!] - {worm}")

    print()
    print_colour("[*] Backdoors:")
    for backdoor in ["antsword"]:
        print_colour(f"[!] - {backdoor}")

    print()
    print_colour("[*] Exposures:")
    for exposure in ["robots-txt", "security-txt", "sitemap"]:
        print_colour(f"[!] - {exposure}")

    print()
    print_colour("[*] Instances:")
    for instance in [
        "wordpress", "microsoft", "server", "webmin", "thinkphp",
        "weblogic", "drupal", "ncast", "jira", "joomla", "zimbra",
        "apache", "php", "webdav", "moveit", "nginx", "bigip"
    ]:
        print_colour(f"[!] - {instance}")

    print()
    print_colour("[*] Network Checks:")
    for network in ["telnet", "rdp", "rtsp", "adb-misconfig", "port-scanner"]:
        print_colour(f"[!] - {network}")

    print()
    print_colour("[*] IoT Checks:")
    for iot in [
        "gargoyle", "gpon", "webcamxp", "netgear", "hikvision",
        "cisco", "epmp", "network-camera", "routeros"
    ]:
        print_colour(f"[!] - {iot}")

    print()
    print_colour("[*] Miscellaneous Checks:")
    for misc in ["dir-listing"]:
        print_colour(f"[!] - {misc}")

    print()
    print_colour("[*] Vulnerabilities:")
    for vuln in [
        "CVE-2016-6277", "CVE-2024-0305", "CVE-2018-13379", "CVE-2017-7921",
        "CVE-2019-17382", "CVE-2019-1653", "CVE-2022-47945", "CVE-2021-36260",
        "CVE-2017-5487", "CVE-2017-7925", "CVE-2022-40684", "CVE-2021-34473",
        "CVE-2023-23752", "CVE-2015-1635", "CVE-2022-1388", "CVE-2021-22986",
        "traversal"
    ]:
        print_colour(f"[!] - {vuln}")

    print()
    print_colour("[*] Workflow Scans:")
    for wf in ["microsoft"]:
        print_colour(f"[!] - {wf}")


def print_scan_context(kwargs):
    if kwargs['output_file']:
        print_colour(f"[*] Results will be saved to: {kwargs['output_file']}")

    print_colour(f"[*] Using {kwargs['threads']} threads with {kwargs['timeout']}s timeout")
    print_colour("----------------------------------------")

    active_scans = []
    for key in ["backdoor", "vuln", "instance", "exposure", "iot", "miscellaneous", "network", "worm"]:
        if kwargs[key]:
            active_scans.append(f"{key.capitalize()} checks: {kwargs[key]}")

    if active_scans:
        print_colour("[*] Active scan modules:")
        for scan in active_scans:
            print_colour(f"    - {scan}")
    else:
        print_colour("[*] No specific scan modules activated - checking open ports only")

def open_output_file(path):
    if path:
        output = safe_open_file(path, 'a')
        if not output:
            print_red(f"Unable to open output file '{path}'. Results will only be shown on screen.")
        return output
    return None

def handle_random_scan(n_targets, kwargs, output_file):
    total_checked = 0
    found_count = 0
    counter_lock = threading.Lock()
    found_targets = []
    total_to_scan = n_targets * 20

    def generate_ip_batch(batch_size):
        for _ in range(batch_size):
            yield generate_ip()

    def process_and_update(ip):
        nonlocal total_checked, found_count
        result = process_ip(ip, kwargs)
        with counter_lock:
            total_checked += 1
            progress_bar.title(f"Scanning Internet [{total_checked}/{total_to_scan}] - Found {found_count}/{n_targets}")
            progress_bar()
            if result:
                found_targets.append(result)
                found_count += 1
                if output_file:
                    output_file.write(f"{result}\n")
                    output_file.flush()
        return result

    with alive_bar(total_to_scan, title="Scanning Internet", enrich_print=False, bar=kwargs['bar_style'], stats=True, unit=" IPs") as progress_bar:
        while found_count < n_targets:
            ip_batch = generate_ip_batch(kwargs['threads'] * 10)
            with concurrent.futures.ThreadPoolExecutor(max_workers=kwargs['threads']) as executor:
                list(executor.map(process_and_update, ip_batch))

            if found_count >= n_targets:
                break
            if total_checked >= total_to_scan:
                old_total = total_to_scan
                total_to_scan = int(total_to_scan * 1.5)
                progress_bar.total = total_to_scan
                print_colour(f"[*] Increasing scan estimate: {old_total} -> {total_to_scan}")

    print()
    print_colour(f"[+] Scan complete - Found {found_count}/{n_targets} targets (Checked {total_checked} IPs)")
    return found_targets

def handle_known_ips(ip_addresses, kwargs, output_file):
    total_ips = len(ip_addresses)
    found_count = 0
    ips_processed = 0
    counter_lock = threading.Lock()
    found_targets = []

    def process_and_update(ip):
        nonlocal ips_processed, found_count
        result = process_ip(ip, kwargs)
        with counter_lock:
            ips_processed += 1
            progress_bar.title(f"Scanning IPs [{ips_processed}/{total_ips}] - Found {found_count}")
            progress_bar()
            if result:
                found_targets.append(result)
                found_count += 1
                if output_file:
                    output_file.write(f"{result}\n")
                    output_file.flush()
        return result

    with alive_bar(
        total_ips,
        title="Scanning targets",
        enrich_print=False,
        bar=kwargs['bar_style'],
        stats=True,
        unit=" IPs"
    ) as progress_bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=kwargs['threads']) as executor:
            list(executor.map(process_and_update, ip_addresses))

    print()
    print_colour(f"[+] Scan complete - Found {found_count} targets")
    return found_targets



@click.command(help="INtrack - Internet Crawler (rich_click).")
@click.option("-H", "--host", type=str, help="Specify a single target IP or subnet range of IPs to scan /24, /23, /22, etc.")
@click.option("-f", "--file", "filename", type=str, help="Specify a file containing target IPs.")
@click.option("-n", "--n-targets", "n_targets", type=int, help="Number of targets to find. Can also be used to increase the range of the scan.")
@click.option("-p", "--port", default="80", help="Port(s) to check. Defaults to 80 if not provided.")
@click.option("-t", "--threads", default=25, help="Number of threads to use.")
@click.option("-o", "--output", "output_file", type=str, help="Store results into a file.")
@click.option("-L", "--lhost", type=str, help="Add a listening host for revshells.")
@click.option("-P", "--lport", type=str, help="A listening port for revshells.")
@click.option("--hostname", is_flag=True, help="Resolve hostnames for IP addresses.")
@click.option("-i", "--instance", type=str, help="Type of instance to check.")
@click.option("-b", "--backdoor", type=str, help="Look for backdoor implants.")
@click.option("-w", "--worm", type=str, help="Enable special script execution with a specified type (e.g., 'vscode-sftp').")
@click.option("-v", "--vuln", type=str, help="Enable vuln script execution with a specified type (e.g., CVE-2017-7921).")
@click.option("-e", "--exposure", type=str, help="Used to detect exposure files.")
@click.option("--iot", type=str, help="Used to detect IoT devices.")
@click.option("-m", "--miscellaneous", type=str, help="Used for miscellaneous checks.")
@click.option("--workflows", type=str, help="Run workflow scans on your targets.")
@click.option("-N", "--network", type=str, help="Used for network scans.")
@click.option("--timeout", default=10, help="Timeout seconds for web requests.")
@click.option("--probe", is_flag=True, help="Used for probing hosts for HTTP/HTTPS")
@click.option("-s", "--spider", type=str, help="Specify the subnet range to scan if a result is found (e.g., /20, /24).")
@click.option("--list", "list_flag", is_flag=True, help="List available scanners and checks.")
@click.option("--bar-style", default="smooth", type=click.Choice(["smooth", "blocks", "bubbles", "solid", "classic", "brackets"]), help="Progress bar style (default 'smooth').")
def main(**kwargs):
    ascii_art()

    config_handler.set_global(spinner='dots_waves', force_tty=True, dual_line=True)

    if kwargs['list_flag']:
        list_scanners()
        sys.exit(0)

    if not (kwargs['host'] or kwargs['filename'] or kwargs['n_targets']):
        print_red("You must provide either --host, --f, or --n")
        sys.exit(1)

    output_file = open_output_file(kwargs['output_file'])

    if kwargs['filename']:
        ip_addresses = read_targets_from_file(kwargs['filename'])
        print_colour(f"[*] Scanning {len(ip_addresses)} targets from file '{kwargs['filename']}'")
        found = handle_known_ips(ip_addresses, kwargs, output_file)

    elif kwargs['host']:
        if '/' in kwargs['host']:
            ip_addresses = get_ips_from_subnet(kwargs['host'])
            print_colour(f"[*] Scanning {len(ip_addresses)} targets from subnet '{kwargs['host']}'")
        else:
            ip_addresses = [kwargs['host']]
            print_colour(f"[*] Scanning 1 target: {kwargs['host']}")
        found = handle_known_ips(ip_addresses, kwargs, output_file)

    else:
        print_colour(f"[*] Scanning {kwargs['n_targets']} random targets from the internet")
        found = handle_random_scan(kwargs['n_targets'], kwargs, output_file)

    print_scan_context(kwargs)

    if output_file:
        output_file.close()

    for t in found[: kwargs['n_targets']] if kwargs['n_targets'] else found:
        print(t)

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())