import os
import datetime
from fpdf import FPDF


# -----------------------------
# MITRE ATT&CK MAP
# -----------------------------
MITRE_MAP = {
    "ssh_bruteforce": "T1110.001 - Password Guessing",
    "port_scan": "T1046 - Network Service Discovery",
    "malware_detected": "T1204 - User Execution",
    "privilege_escalation": "T1068 - Exploitation for Privilege Escalation"
}


# -----------------------------
# EXECUTIVE SUMMARY
# -----------------------------
def generate_summary(event):
    return (
        f"A {event['attack'].replace('_', ' ')} activity was detected targeting "
        f"{event['target']} originating from {event['source_ip']}. "
        f"The system classified this as {event['severity']} severity. "
        f"No confirmed compromise was identified."
    )


# -----------------------------
# REPORT BUILDER
# -----------------------------
def build_report(event):
    return {
        "id": f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "time": datetime.datetime.now().isoformat(),
        "attack": event["attack"],
        "source_ip": event["source_ip"],
        "target": event["target"],
        "severity": event["severity"],
        "fails": event.get("fails", 0),
        "mitre": MITRE_MAP.get(event["attack"], "T0000 - Unknown"),
        "summary": generate_summary(event)
    }


# -----------------------------
# HTML GENERATOR
# -----------------------------
def save_html(report, path):
    html = f"""
    <html>
    <head>
        <title>SOC Incident Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            .box {{ padding: 10px; border: 1px solid #ddd; margin-bottom: 15px; }}
        </style>
    </head>
    <body>

    <h1>🛡️ SOC Tier 1 Incident Report</h1>

    <div class="box">
        <h3>Incident ID</h3>
        <p>{report['id']}</p>
    </div>

    <div class="box">
        <h3>Executive Summary</h3>
        <p>{report['summary']}</p>
    </div>

    <div class="box">
        <h3>Technical Details</h3>
        <p><b>Source IP:</b> {report['source_ip']}</p>
        <p><b>Target:</b> {report['target']}</p>
        <p><b>Failed Attempts:</b> {report['fails']}</p>
        <p><b>Severity:</b> {report['severity']}</p>
    </div>

    <div class="box">
        <h3>MITRE ATT&CK</h3>
        <p>{report['mitre']}</p>
    </div>

    <div class="box">
        <h3>Conclusion</h3>
        <p>Incident analyzed by SOC Tier 1 detection system. No breach confirmed.</p>
    </div>

    </body>
    </html>
    """

    with open(path, "w") as f:
        f.write(html)


# -----------------------------
# PDF GENERATOR
# -----------------------------
def save_pdf(report, path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="SOC Tier 1 Incident Report", ln=True, align="C")
    pdf.ln(10)

    pdf.multi_cell(0, 10, f"""
Incident ID: {report['id']}
Time: {report['time']}

Executive Summary:
{report['summary']}

Source IP: {report['source_ip']}
Target: {report['target']}
Severity: {report['severity']}
Failed Attempts: {report['fails']}

MITRE ATT&CK:
{report['mitre']}
""")

    pdf.output(path)


# -----------------------------
# MAIN PIPELINE
# -----------------------------
if __name__ == "__main__":

    event = {
        "attack": "ssh_bruteforce",
        "source_ip": "192.168.88.50",
        "target": "192.168.88.4",
        "fails": 47,
        "severity": "HIGH"
    }

    report = build_report(event)

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")

    pdf_path = os.path.join(desktop, f"SOC_Report_{report['id']}.pdf")
    html_path = os.path.join(desktop, "soc_report.html")

    save_pdf(report, pdf_path)
    save_html(report, html_path)

    print("[✓] PDF Generated:", pdf_path)
    print("[✓] HTML Generated:", html_path)
