import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour


def check_sensitive_endpoints(ip: str, ports=None, timeout=5):
    headers = {"User-Agent": user_agents()}
    protocols = ["http", "https"]
    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]
    
    status_info_dashboard_paths = [
        "/server-status",
        "/status",
        "/stats",
        "/server-info",
        "/nginx_status",
        "/_status",
        "/server_status",
        "/apache-status",
        "/apache_status",
        "/server/stats",
        "/monitoring",
        "/server/status"
    ]
    
    phpinfo_paths = [
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
        "/test.php",
        "/i.php",
        "/infophp.php",
        "/phpinfo",
        "/phpinfo.php",
        "/info.php",
        "/php_info.php",
        "/test.php",
        "/i.php",
        "/infophp.php",
    ]

    dashboard_paths = [
        "/dashboard",
        "/admin",
        "/admin/dashboard",
        "/admin-panel",
        "/management",
        "/control",
        "/panel",
        "/console",
        "/statistics",
        "/monitor",
        "/grafana",
        "/kibana",
        "/prometheus",
        "/metrics",
        "/nagios",
        "/zabbix",
        "/admin/monitoring",
        "/status-dashboard",
    ]

    monitoring_paths = [
        "/munin",
        "/cacti",
        "/netdata",
        "/monitor/",
        "/prtg/",
        "/check_mk/",
        "/centreon",
        "/icinga/",
        "/observium/",
        "/ganglia/"
    ]
    
    
    for port in ports:
        for protocol in protocols:
            base_url = f"{protocol}://{ip}{port}"
            for path_status in status_info_dashboard_paths:
                url = f"{base_url}{path_status}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200:
                        print(f"[+] {url}")
                        return True
                except requests.RequestException:
                    continue
            for path_dashboard in dashboard_paths:
                url = f"{base_url}{path_dashboard}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200:
                        print(f"[+] {url}")
                        return True
                except requests.RequestException:
                    continue
            for path_monitoring in monitoring_paths:
                url = f"{base_url}{path_monitoring}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200:
                        print(f"[+] {url}")
                        return True
                except requests.RequestException:
                    continue
            for path_phpinfo in phpinfo_paths:
                url = f"{base_url}{path_phpinfo}"
                try:
                    response = requests.get(url, headers=headers, verify=False, timeout=timeout)
                    if response.status_code == 200:
                        print(f"[+] {url}")
                        return True
                except requests.RequestException:
                    continue
            
    return False