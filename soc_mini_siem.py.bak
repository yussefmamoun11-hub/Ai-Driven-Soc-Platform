import os
import time
import json
import datetime
from fpdf import FPDF


# -----------------------------
# MITRE MAP
# -----------------------------
MITRE_MAP = {
    "ssh_bruteforce": "T1110.001",
    "port_scan": "T1046",
    "malware_detected": "T1204",
}


# -----------------------------
# DETECTION ENGINE
# -----------------------------
def detect_attack(event):
    if event["type"] == "ssh_failed_login" and event["count"] > 20:
        return "ssh_bruteforce", "HIGH"

    if event["type"] == "port_scan" and event["ports"] > 100:
        return "port_scan", "MEDIUM"

    return "normal", "LOW"


# -----------------------------
# WRITEUP ENGINE
# -----------------------------
def build_report(event, attack, severity):
    return {
        "id": f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "time": datetime.datetime.now().isoformat(),
        "source_ip": event["source_ip"],
        "target": event["target"],
        "attack": attack,
        "severity": severity,
        "mitre": MITRE_MAP.get(attack, "T0000"),
        "summary": f"Detected {attack} from {event['source_ip']} targeting {event['target']}"
    }


# -----------------------------
# PDF GENERATOR
# -----------------------------
def save_pdf(report, path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, "SOC INCIDENT REPORT", ln=True, align="C")
    pdf.ln(10)

    pdf.multi_cell(0, 10, f"""
Incident ID: {report['id']}
Time: {report['time']}
Source IP: {report['source_ip']}
Target: {report['target']}
Attack: {report['attack']}
Severity: {report['severity']}
MITRE: {report['mitre']}

Summary:
{report['summary']}
""")

    pdf.output(path)


# -----------------------------
# HTML GENERATOR
# -----------------------------
def save_html(report, path):
    html = f"""
    <html>
    <body>
        <h1>SOC INCIDENT</h1>
        <p><b>ID:</b> {report['id']}</p>
        <p><b>Attack:</b> {report['attack']}</p>
        <p><b>Severity:</b> {report['severity']}</p>
        <p><b>Source:</b> {report['source_ip']}</p>
        <p><b>Target:</b> {report['target']}</p>
        <p><b>MITRE:</b> {report['mitre']}</p>
        <p>{report['summary']}</p>
    </body>
    </html>
    """

    with open(path, "w") as f:
        f.write(html)


# -----------------------------
# LOG STORAGE (SIEM MEMORY)
# -----------------------------
def save_log(report):
    os.makedirs("siem_logs", exist_ok=True)
    file_path = "siem_logs/incidents.json"

    logs = []
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            logs = json.load(f)

    logs.append(report)

    with open(file_path, "w") as f:
        json.dump(logs, f, indent=2)


# -----------------------------
# SIMULATED LIVE EVENTS
# -----------------------------
def generate_event_stream():
    events = [
        {"type": "ssh_failed_login", "count": 5, "source_ip": "10.0.0.2", "target": "192.168.1.10"},
        {"type": "ssh_failed_login", "count": 50, "source_ip": "10.0.0.99", "target": "192.168.1.10"},
        {"type": "port_scan", "ports": 150, "source_ip": "10.0.0.77", "target": "192.168.1.10"},
    ]
    return events


# -----------------------------
# MAIN LOOP (REAL SIEM ENGINE)
# -----------------------------
def run_siem():
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")

    events = generate_event_stream()

    for event in events:
        attack, severity = detect_attack(event)

        if attack == "normal":
            continue

        report = build_report(event, attack, severity)

        pdf_path = os.path.join(desktop, f"{report['id']}.pdf")
        html_path = os.path.join(desktop, f"{report['id']}.html")

        save_pdf(report, pdf_path)
        save_html(report, html_path)
        save_log(report)

        print(f"[ALERT] {attack} detected from {event['source_ip']}")
        print("[+] PDF:", pdf_path)
        print("[+] HTML:", html_path)
        print("-------------------------------------------------")


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    run_siem()

