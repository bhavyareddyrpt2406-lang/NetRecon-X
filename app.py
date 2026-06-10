from flask import Flask, render_template, request, send_file
from reportlab.pdfgen import canvas
import socket

app = Flask(__name__)

PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

RISKY_PORTS = {
    21: "FTP",
    23: "Telnet"
}


def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        sock.connect((ip, port))

        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "Banner not available"

        sock.close()
        return banner

    except:
        return "Banner not available"


def scan_target(target):

    results = []
    risk_score = 0

    try:

        target_ip = socket.gethostbyname(target)

        for port, service in PORTS.items():

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            result = s.connect_ex((target_ip, port))

            if result == 0:

                banner = grab_banner(target_ip, port)

                results.append({
                    "port": port,
                    "service": service,
                    "banner": banner
                })

                if port in RISKY_PORTS:
                    risk_score += 1

            s.close()

        if len(results) == 0:
            results.append({
                "port": "None",
                "service": "No open ports found",
                "banner": "-"
            })

        if risk_score == 0:
            risk_level = "LOW"
        elif risk_score == 1:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        return results, risk_level

    except Exception as e:

        results.append({
            "port": "Error",
            "service": str(e),
            "banner": "-"
        })

        return results, "LOW"


def generate_pdf(results):

    pdf = canvas.Canvas("scan_report.pdf")

    y = 800

    pdf.drawString(100, y, "NetRecon-X Scan Report")
    y -= 40

    for result in results:

        line = f"Port {result['port']} - {result['service']}"

        pdf.drawString(100, y, line)
        y -= 20

        pdf.drawString(
            120,
            y,
            f"Banner: {result['banner']}"
        )

        y -= 30

    pdf.save()


@app.route("/", methods=["GET", "POST"])
def home():

    results = []
    history = []
    risk_level = None

    if request.method == "POST":

        target = request.form["target"]

        results, risk_level = scan_target(target)

        generate_pdf(results)

        with open("scan_history.txt", "a") as file:
            file.write(target + "\n")

    try:
        with open("scan_history.txt", "r") as file:
            history = file.readlines()

    except:
        history = []

    return render_template(
        "dashboard.html",
        results=results,
        history=history,
        risk_level=risk_level
    )


@app.route("/download")
def download():

    return send_file(
        "scan_report.pdf",
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)