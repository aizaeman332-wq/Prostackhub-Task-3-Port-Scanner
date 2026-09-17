from flask import Flask, render_template, request
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# --------------------------------------------------
# Security: allow only localhost/private lab IPs
# --------------------------------------------------
def is_allowed_ip(target):
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


# --------------------------------------------------
# Common port services
# --------------------------------------------------
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy"
}


# --------------------------------------------------
# Scan one port
# --------------------------------------------------
def scan_port(target, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Short timeout keeps scanner responsive
    sock.settimeout(0.4)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = COMMON_SERVICES.get(port, "Unknown")

            return {
                "port": port,
                "service": service,
                "status": "Open"
            }

    except (socket.timeout, OSError):
        pass

    finally:
        sock.close()

    return None


# --------------------------------------------------
# Scan ports 1-1024
# --------------------------------------------------
def scan_ports(target):

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        results = executor.map(
            lambda port: scan_port(target, port),
            range(1, 1025)
        )

        for result in results:
            if result:
                open_ports.append(result)

    return open_ports


# --------------------------------------------------
# Home page
# --------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():

    results = []
    target = ""
    error = ""

    if request.method == "POST":

        target = request.form.get("target", "").strip()

        if not target:
            error = "Please enter an IP address."

        elif not is_allowed_ip(target):
            error = (
                "For safety, this scanner accepts only "
                "localhost or private/lab IP addresses."
            )

        else:
            try:
                results = scan_ports(target)

            except Exception as e:
                error = f"Scanning error: {e}"

    return render_template(
        "index.html",
        results=results,
        target=target,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True, port=5002)