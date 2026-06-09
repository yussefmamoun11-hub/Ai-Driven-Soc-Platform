import os
import json
import datetime
from flask import Flask, jsonify, render_template_string
from fpdf import FPDF


app = Flask(__name__)

DB_FILE = "siem_db.json"


# -----------------------------
# INIT DB
# -----------------------------
def load_db():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


# -----------------------------
# AI ANALYST (SIMULATED)
# -----------------------------
def ai_analysis(event):
    attack = event["attack"]

    if attack == "ssh_bruteforce":
        return "Brute force SSH attack detected. High probability of credential stuffing attempt."

    if attack == "port_scan":
        return "Network reconnaissance detected. Attacker scanning multiple ports."

    if attack == "malware":
        return "Possible malware execution attempt detected."

    return "Suspicious activity detected."


# -----------------------------
# MITRE MAPPING
# -----------------------------
MITRE = {
    "ssh_bruteforce": "T1110.001",
    "port_scan": "T1046",
    "malware": "T1204"
}


# -----------------------------
# CREATE INCIDENT
# -----------------------------
def create_incident(event):
    db = load_db()

    incident = {
        "id": f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "time": datetime.datetime.now().isoformat(),
        "source_ip": event["source_ip"],
        "target": event["target"],
        "attack": event["attack"],
        "severity": event["severity"],
        "mitre": MITRE.get(event["attack"], "T0000"),
        "analysis": ai_analysis(event)
    }

    db.append(incident)
    save_db(db)

    return incident


# -----------------------------
# PDF REPORT
# -----------------------------
def generate_pdf(incident):
    path = f"Desktop/{incident['id']}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, "SOC AI ANALYST REPORT", ln=True, align="C")
    pdf.ln(10)

    pdf.multi_cell(0, 10, f"""
Incident ID: {incident['id']}
Time: {incident['time']}
Source IP: {incident['source_ip']}
Target: {incident['target']}
Attack: {incident['attack']}
Severity: {incident['severity']}
MITRE: {incident['mitre']}

AI Analysis:
{incident['analysis']}
""")

    pdf.output(path)
    return path


# -----------------------------
# DASHBOARD UI
# -----------------------------
HTML_PAGE = """
<html>
<head>
<title>SOC Dashboard</title>
<style>
body { font-family: Arial; margin: 40px; }
.card { border: 1px solid #ddd; padding: 10px; margin: 10px; }
</style>
</head>
<body>

<h1>🛡️ SOC AI Dashboard</h1>

{% for i in incidents %}
<div class="card">
    <p><b>ID:</b> {{i.id}}</p>
    <p><b>Attack:</b> {{i.attack}}</p>
    <p><b>Severity:</b> {{i.severity}}</p>
    <p><b>Source:</b> {{i.source_ip}}</p>
    <p><b>Analysis:</b> {{i.analysis}}</p>
</div>
{% endfor %}

</body>
</html>
"""


@app.route("/")
def dashboard():
    incidents = load_db()
    return render_template_string(HTML_PAGE, incidents=incidents)


@app.route("/api/incidents")
def api():
    return jsonify(load_db())


# -----------------------------
# SIMULATED ATTACK INPUT
# -----------------------------
def simulate_attack():
    return [
        {"attack": "ssh_bruteforce", "source_ip": "10.0.0.5", "target": "192.168.1.10", "severity": "HIGH"},
        {"attack": "port_scan", "source_ip": "10.0.0.9", "target": "192.168.1.10", "severity": "MEDIUM"},
    ]


# -----------------------------
# RUN PIPELINE
# -----------------------------
def run_pipeline():
    for event in simulate_attack():
        incident = create_incident(event)

        pdf_path = generate_pdf(incident)

        print("\n[ALERT]")
        print("Incident:", incident["id"])
        print("Attack:", incident["attack"])
        print("AI:", incident["analysis"])
        print("PDF:", pdf_path)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    import threading

    # run detection first
    run_pipeline()

    # start dashboard
    print("\n[+] Starting SOC Dashboard at http://127.0.0.1:5000")
    app.run(debug=False)
