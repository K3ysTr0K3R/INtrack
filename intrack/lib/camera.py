import requests
from urllib.parse import urljoin
import hashlib
import re
from .color_handler import print_colour

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CAMERA_RULES = [
    {"brand": "avtech", "path": "/", "cond": "title=`::: Login :::`", "exclude": "", "case": False},
    {"brand": "avtech", "path": "/", "cond": "title=`Remote Surveillance`&&title=`Any time & Any where`", "exclude": "", "case": False},
    {"brand": "avtech", "path": "/nobody/favicon.ico", "cond": "md5=`6a7e13b3f9197a383c96618fe32e345a`", "exclude": "", "case": True},
    {"brand": "axis", "path": "/favicon.ico", "cond": "md5=`a3fd8705f010b90e37d42128000f620b`", "exclude": "", "case": True},
    {"brand": "cctv", "path": "/", "cond": "body=`IP Surveillance for Your Life`", "exclude": "", "case": False},
    {"brand": "cctv", "path": "/", "cond": "body=`/nobody/loginDevice.js`", "exclude": "", "case": False},
    {"brand": "cctv", "path": "/", "cond": "headers=`JAWS`", "exclude": "", "case": False},
    {"brand": "dahua", "path": "/", "cond": "body=`WEB SERVICE`", "exclude": "", "case": False},
    {"brand": "dahua", "path": "/", "cond": "title=`WEB SERVICE`", "exclude": "", "case": False},
    {"brand": "cctv", "path": "/favicon.ico", "cond": "md5=`f066b751b858f75ef46536f5b357972b`", "exclude": "", "case": True},
    {"brand": "dahua", "path": "/favicon.ico", "cond": "md5=`bd9e17c46bbbc18af2a2bd718dddad0e`", "exclude": "", "case": True},
    {"brand": "dahua", "path": "/favicon.ico", "cond": "md5=`605f51b413980667766a9aff2e53b9ed`", "exclude": "", "case": True},
    {"brand": "dahua", "path": "/favicon.ico", "cond": "md5=`b39f249362a2e4ab62be4ddbc9125f53`", "exclude": "", "case": True},
    {"brand": "dahua", "path": "/image/lgbg.jpg", "cond": "md5=`4ff53be6165e430af41d782e00207fda`", "exclude": "", "case": True},
    {"brand": "dlink-dcs", "path": "/", "cond": "headers=`realm=\"DCS`", "exclude": "", "case": False},
    {"brand": "dlink-dcs", "path": "/", "cond": "headers=`realm=DCS`", "exclude": "", "case": False},
    {"brand": "dvr", "path": "/login.rsp", "cond": "title=`LOGIN`", "exclude": "", "case": False},
    {"brand": "geovision", "path": "/", "cond": "title=`GeoVision`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "body=`doc/page/login.asp`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "body=`g_szCacheTime`&&body=`iVMS`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`Webs`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`APP-webs`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`DVRDVS-Webs`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`DNVRS-Webs`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`Hikvision-Webs`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "headers=`_goaheadwebSessionId`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/", "cond": "title=`hikvision`", "exclude": "", "case": False},
    {"brand": "hikvision", "path": "/favicon.ico", "cond": "md5=`89b932fcc47cf4ca3faadb0cfdef89cf`", "exclude": "", "case": True},
    {"brand": "instar", "path": "/", "cond": "title=`INSTAR`&&title=`Camera`", "exclude": "", "case": False},
    {"brand": "ipcamera", "path": "/", "cond": "headers=`IPCamera`&&status_code=`401`", "exclude": "", "case": False},
    {"brand": "netwave", "path": "/", "cond": "headers=`Netwave IP Camera`", "exclude": "", "case": False},
    {"brand": "nuuo", "path": "/", "cond": "title=`network video recorder login`", "exclude": "", "case": False},
    {"brand": "reecam", "path": "/", "cond": "headers=`ReeCam IP Camera`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda | login`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda|login`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda | 登录`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda|登录`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda | Web Master`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/", "cond": "title=`Tenda | Wireless Router`", "exclude": "", "case": False},
    {"brand": "tenda", "path": "/favicon.ico", "cond": "md5=`fa31b29eab2da688b11d8fafc5fc6b27`", "exclude": "", "case": True},
    {"brand": "uniview", "path": "/favicon.ico", "cond": "md5=`1536f25632f78fb03babedcb156d3f69`", "exclude": "", "case": True},
    {"brand": "uniview", "path": "/skin/default_1/images/logo.png", "cond": "md5=`c30a692ad0d1324389485de06c96d9b8`", "exclude": "", "case": True},
    {"brand": "xiongmai", "path": "/", "cond": "title=`NETSurveillance WEB`", "exclude": "", "case": False},
    {"brand": "xiongmai", "path": "/", "cond": "title=`NetSurveillance WEB`", "exclude": "", "case": False},
]

def _fetch(url, timeout):
    try:
        resp = requests.get(url, timeout=timeout, verify=False, stream=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        body = b""
        for chunk in resp.iter_content(1024):
            body += chunk
            if len(body) > 2 * 1024 * 1024:
                break
        return resp, body
    except Exception:
        return None, None

def _normalize(s, case_sensitive):
    return s if case_sensitive else s.lower()

def _extract_title(html_bytes):
    try:
        text = html_bytes.decode("utf-8", errors="ignore")
    except:
        text = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""

def _check_condition(resp, body, cond, case_sensitive):
    """Evaluate a single condition string (key=value)."""
    if "=" not in cond:
        return False
    key, val = cond.split("=", 1)
    val = val.strip("` ")

    if key == "title":
        title = _extract_title(body)
        return _normalize(val, case_sensitive) in _normalize(title, case_sensitive)
    elif key == "body":
        return _normalize(val, case_sensitive) in _normalize(body.decode("utf-8", errors="ignore"), case_sensitive)
    elif key == "headers":
        for name, values in resp.headers.items():
            if _normalize(val, case_sensitive) in _normalize(name, case_sensitive):
                return True
            for v in values if isinstance(values, list) else [values]:
                if _normalize(val, case_sensitive) in _normalize(v, case_sensitive):
                    return True
        return False
    elif key == "md5":
        return hashlib.md5(body).hexdigest() == val
    elif key == "status_code":
        return str(resp.status_code) == val
    return False

def mass_camera_detect(ip, open_ports, timeout=2):
    use_https = (443 in open_ports) and (80 not in open_ports)
    base_url = f"https://{ip}" if use_https else f"http://{ip}"

    try:
        requests.head(base_url, timeout=1, verify=False)
    except Exception:
        return False

    cache = {}

    def get_resp(path):
        full_url = urljoin(base_url, path)
        if full_url not in cache:
            cache[full_url] = _fetch(full_url, timeout)
        return cache[full_url]

    detected_brands = []

    for rule in CAMERA_RULES:
        resp, body = get_resp(rule["path"])
        if resp is None:
            continue

        if rule.get("exclude"):
            if _normalize(rule["exclude"], rule["case"]) in _normalize(body.decode("utf-8", errors="ignore"), rule["case"]):
                continue

        conditions = [c.strip() for c in rule["cond"].split("&&")]
        if all(_check_condition(resp, body, cond, rule["case"]) for cond in conditions):
            if rule["brand"] not in detected_brands:
                detected_brands.append(rule["brand"])

    if detected_brands:
        print_colour(f"[+] Camera detected: {ip} -> {', '.join(detected_brands)}")
        return True
    return False
