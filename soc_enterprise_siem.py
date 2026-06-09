import json
import os
import datetime
import random
from flask import Flask, render_template_string, jsonify
from fpdf import FPDF

app = Flask(__name__)

DB_FILE = "enterprise_siem.json"


# -----------------------------
# DB HANDLER
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
# THREAT SCORING
# -----------------------------
def score_threat(event):
    base = {
        "ssh_bruteforce": 85,
        "port_scan": 60,
        "malware": 95
    }.get(event["attack"], 30)

    return max(0, min(100, base + random.randint(-8, 8)))


# -----------------------------
# AI ANALYSIS ENGINE
# -----------------------------
def ai_analysis(score):
    if score >= 85:
        return "Active intrusion detected with high confidence. Immediate response required."
    elif score >= 60:
        return "Suspicious activity detected. Monitoring recommended."
    return "Low risk anomaly detected."


# -----------------------------
# MITRE MAPPING
# -----------------------------
MITRE = {
    "ssh_bruteforce": "T1110.001",
    "port_scan": "T1046",
    "malware": "T1204"
}


# -----------------------------
# INCIDENT CREATION
# -----------------------------
def create_incident(event):
    score = score_threat(event)
    analysis = ai_analysis(score)

    incident = {
        "id": f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')}",
        "time": datetime.datetime.now().isoformat(),
        "attack": event["attack"],
        "source_ip": event["source_ip"],
        "target": event["target"],
        "score": score,
        "severity": "CRITICAL" if score >= 85 else "MEDIUM" if score >= 60 else "LOW",
        "mitre": MITRE.get(event["attack"], "T0000"),
        "analysis": analysis
    }

    return incident


# -----------------------------
# PDF GENERATOR (AUTO DESKTOP EXPORT)
# -----------------------------
def generate_pdf(incident):
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    path = os.path.join(desktop, f"{incident['id']}.pdf")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, "SOC ENTERPRISE INCIDENT REPORT", ln=True, align="C")
    pdf.ln(10)

    pdf.multi_cell(0, 10, f"""
Incident ID: {incident['id']}
Time: {incident['time']}

Attack: {incident['attack']}
Score: {incident['score']}
Severity: {incident['severity']}
Source IP: {incident['source_ip']}
Target: {incident['target']}
MITRE: {incident['mitre']}

AI ANALYSIS:
{incident['analysis']}
""")

    pdf.output(path)
    print(f"[+] PDF Generated -> {path}")


# -----------------------------
# SIMULATED STREAM
# -----------------------------
def generate_stream():
    return [
        {"attack": "ssh_bruteforce", "source_ip": "10.0.0.5", "target": "192.168.1.10"},
        {"attack": "port_scan", "source_ip": "10.0.0.8", "target": "192.168.1.10"},
        {"attack": "malware", "source_ip": "10.0.0.99", "target": "192.168.1.10"}
    ]


# -----------------------------
# PROCESS ENGINE
# -----------------------------
def run_engine():
    db = load_db()

    incidents = []

    for event in generate_stream():
        incident = create_incident(event)
        incidents.append(incident)

        # 🔥 AUTO PDF GENERATION HERE
        generate_pdf(incident)

        print("\n🚨 ALERT")
        print("Attack:", incident["attack"])
        print("Score:", incident["score"])
        print("Severity:", incident["severity"])
        print("Analysis:", incident["analysis"])

    db.extend(incidents)
    save_db(db)


# -----------------------------
# DASHBOARD UI
# -----------------------------
HTML = """
<html>
<head>
<title>SOC Enterprise Dashboard</title>
<style>
body { font-family: Arial; margin: 30px; }
.card { border: 1px solid #ccc; padding: 10px; margin: 10px; }
</style>
</head>
<body>

<h1>🛡️ SOC Enterprise Dashboard</h1>

{% for i in data %}
<div class="card">
    <p><b>ID:</b> {{i.id}}</p>
    <p><b>Attack:</b> {{i.attack}}</p>
    <p><b>Score:</b> {{i.score}}</p>
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
    return render_template_string(HTML, data=load_db())


@app.route("/api")
def api():
    return jsonify(load_db())


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    run_engine()
    print("\n🔥 SOC Enterprise Running -> http://127.0.0.1:5000")
    app.run(debug=False)
