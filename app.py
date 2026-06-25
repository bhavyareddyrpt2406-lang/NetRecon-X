from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for
)
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


def scan_target(target, start_port, end_port):

    results = []
    risk_score = 0

    try:

        target_ip = socket.gethostbyname(target)

        for port, service in PORTS.items():

            if port < start_port or port > end_port:
                continue

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

def generate_pdf(results, target, risk_level, target_ip):

    pdf = canvas.Canvas("scan_report.pdf")

    y = 800

    # Title
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(150, y, "NETRECON-X SECURITY REPORT")

    y -= 40

    pdf.setFont("Helvetica", 12)

    pdf.drawString(50, y, f"Target: {target}")
    y -= 20

    pdf.drawString(50, y, f"IP Address: {target_ip}")
    y -= 20

    pdf.drawString(50, y, f"Risk Level: {risk_level}")

    y -= 30

    pdf.line(50, y, 550, y)

    y -= 30

    # Open Ports Section
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "OPEN PORTS")

    y -= 25

    pdf.setFont("Helvetica", 12)

    for result in results:

        pdf.drawString(
            60,
            y,
            f"Port {result['port']} - {result['service']}"
        )

        y -= 20

    y -= 10

    pdf.line(50, y, 550, y)

    y -= 30

    # Banner Section
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "BANNER INFORMATION")

    y -= 25

    pdf.setFont("Helvetica", 12)

    for result in results:

        pdf.drawString(
            60,
            y,
            f"{result['service']}:"
        )

        y -= 20

        banner = str(result['banner'])[:80]

        pdf.drawString(
            80,
            y,
            banner
        )

        y -= 25

    pdf.line(50, y, 550, y)

    y -= 30

    # Recommendations
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "SECURITY RECOMMENDATIONS")

    y -= 25

    pdf.setFont("Helvetica", 12)

    recommendations = [
        "Close unnecessary services",
        "Restrict public exposure of open ports",
        "Disable insecure protocols such as Telnet and FTP",
        "Monitor network activity regularly"
    ]

    for rec in recommendations:

        pdf.drawString(60, y, f"- {rec}")

        y -= 20

    pdf.save()
@app.route("/", methods=["GET", "POST"])
def home():

    results = []
    history = []
    risk_level = None
    target_ip = None
    target_name = None    

    if request.method == "POST":


        target = request.form["target"]

        start_port = int(request.form["start_port"])
        end_port = int(request.form["end_port"])

        if start_port > end_port:
            start_port, end_port = end_port, start_port

        target_name = target
        target_ip = socket.gethostbyname(target)

        results, risk_level = scan_target(
            target,
            start_port,
            end_port
        )

        generate_pdf(
            results,
            target,
            risk_level,
            target_ip
        )

        with open("scan_history.txt", "a") as file:
            file.write(
        f"{target} | Ports {start_port}-{end_port}\n"
    )


    try:
        with open("scan_history.txt", "r") as file:
            history = file.readlines()

    except:
        history = []

    return render_template(
        "dashboard.html",
        results=results,
        history=history,
        risk_level=risk_level,
        target_name=target_name,
        target_ip=target_ip
    )

@app.route("/clear_history")
def clear_history():

    open("scan_history.txt", "w").close()

    return redirect(url_for("home"))

@app.route("/download")
def download():

    return send_file(
        "scan_report.pdf",
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
