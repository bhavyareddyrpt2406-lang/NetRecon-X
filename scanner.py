import socket

ports = {
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

target = input("Enter target IP or hostname: ")

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("\n[ERROR] Invalid IP address or hostname!")
    exit()

print(f"\n[*] Scanning {target_ip}...\n")

results = []

for port, service in ports.items():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((target_ip, port))

    if result == 0:
        output = f"[OPEN] Port {port} - {service}"
        print(output)
        results.append(output)

    s.close()

with open("scan_results.txt", "w") as file:
    if results:
        for line in results:
            file.write(line + "\n")
    else:
        file.write("No open ports found.\n")

print("\n[✓] Scan completed.")
print("[✓] Results saved to scan_results.txt")