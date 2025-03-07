from lib.instances.microsoft_iis import check_microsoft_iis
from lib.vulns.microsoft.CVE_2017_7269 import check_CVE_2017_7269
from lib.vulns.microsoft.CVE_2021_38647 import check_CVE_2021_38647
from lib.vulns.microsoft.CVE_2021_34473 import check_CVE_2021_34473

def check_microsoft_workflow(ip, open_ports):
	if check_microsoft_iis(ip, open_ports):
		check_microsoft_iis(ip, open_ports)
		print(f"Running Windows vuln scans on {ip}")
		check_CVE_2017_7269(ip, open_ports)
		check_CVE_2021_38647(ip, open_ports)
		check_CVE_2021_34473(ip, open_ports)
