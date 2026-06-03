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


def scan_target(target):
    results = []

    try:
        target_ip = socket.gethostbyname(target)

        for port, service in PORTS.items():

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            result = s.connect_ex((target_ip, port))

            if result == 0:
                results.append(f"{port} - {service}")

            s.close()

        if len(results) == 0:
            results.append("-- No open ports found")

    except:
        results.append("Invalid IP Address or Hostname")

    return results


@app.route("/", methods=["GET", "POST"])
def home():

    results = []
    history = []

    if request.method == "POST":

        target = request.form["target"]

        results = scan_target(target)

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


if __name__ == "__main__":
    app.run(debug=True)