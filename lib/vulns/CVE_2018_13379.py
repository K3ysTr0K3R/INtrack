import requests

def check_CVE_2018_13379(ip, port=False):
protocols = ["http", "https"]
ports = ["f:{port}" if port else ""]
for protocol in protocols:
for port_suffix in ports:
url =
try:
if "^var fgt_lang =" in response.text:
print_green("The target is vulnerable to")
