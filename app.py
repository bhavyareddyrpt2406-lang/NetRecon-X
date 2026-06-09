from flask import Flask, render_template, request, send_file
from reportlab.pdfgen import canvas
from flask import Flask, render_template, request
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

                results.append(f"{port} - {service}")
                results.append(f"Banner: {banner}")

                if port in RISKY_PORTS:
                    risk_score += 1

            s.close()

        if len(results) == 0:
            results.append("-- No open ports found")

        if risk_score == 0:
            results.append("Risk Level: LOW")
        elif risk_score == 1:
            results.append("Risk Level: MEDIUM")
        else:
            results.append("Risk Level: HIGH")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results


@app.route("/", methods=["GET", "POST"])
def home():

    results = []
    history = []

    if request.method == "POST":

        target = request.form["target"]

        results = scan_target(target)
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
        history=history
    )
def generate_pdf(results):
    pdf = canvas.Canvas("scan_report.pdf")

    y = 800
    pdf.drawString(100, y, "NetRecon-X Scan Report")

    y -= 40

    for result in results:
        pdf.drawString(100, y, result)
        y -= 20

    pdf.save()

@app.route("/download")
def download():
    return send_file(
        "scan_report.pdf",
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(debug=True)