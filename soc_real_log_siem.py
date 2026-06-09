import os
import re
import json
import datetime
from collections import defaultdict
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

DB_FILE = "real_siem_db.json"
LOG_FILE = "/var/log/auth.log"


# -----------------------------
# LOAD / SAVE DB
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
# PARSE REAL LINUX LOGS
# -----------------------------
def parse_logs():
    incidents = []

    if not os.path.exists(LOG_FILE):
        print("[!] auth.log not found")
        return incidents

    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    for line in logs[-200:]:  # آخر 200 سطر فقط

        # SSH Failed login
        if "Failed password" in line:
            ip = extract_ip(line)

            incidents.append({
                "attack": "ssh_bruteforce",
                "source_ip": ip,
                "target": "localhost",
                "severity": "HIGH",
                "raw": line.strip()
            })

        # Possible sudo abuse
        if "sudo" in line:
            incidents.append({
                "attack": "privilege_escalation",
                "source_ip": "localhost",
                "target": "system",
                "severity": "MEDIUM",
                "raw": line.strip()
            })

    return incidents


# -----------------------------
# EXTRACT IP
# -----------------------------
def extract_ip(text):
    match = re.search(r"[0-9]+(?:\.[0-9]+){3}", text)
    return match.group(0) if match else "unknown"


# -----------------------------
# SCORE ENGINE
# -----------------------------
def score(event):
    if event["attack"] == "ssh_bruteforce":
        return 90
    if event["attack"] == "privilege_escalation":
        return 80
    return 40


# -----------------------------
# ANALYSIS ENGINE
# -----------------------------
def analyze(score_value):
    if score_value >= 85:
        return "CRITICAL: Active intrusion detected from real system logs"
    if score_value >= 60:
        return "WARNING: Suspicious behavior detected"
    return "INFO: Low risk activity"


# -----------------------------
# BUILD INCIDENT
# -----------------------------
def build_incidents():
    db = load_db()
    new_incidents = []

    logs = parse_logs()

    for e in logs:
        sc = score(e)

        incident = {
            "id": f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')}",
            "time": datetime.datetime.now().isoformat(),
            "attack": e["attack"],
            "source_ip": e["source_ip"],
            "target": e["target"],
            "score": sc,
            "severity": "CRITICAL" if sc > 85 else "MEDIUM",
            "analysis": analyze(sc),
            "raw_log": e["raw"]
        }

        new_incidents.append(incident)

    db.extend(new_incidents)
    save_db(db)

    return new_incidents


# -----------------------------
# DASHBOARD
# -----------------------------
HTML = """
<html>
<head>
<title>REAL SOC SIEM</title>
<style>
body { font-family: Arial; margin: 30px; }
.card { border: 1px solid #ccc; padding: 10px; margin: 10px; }
</style>
</head>
<body>

<h1>🛡️ REAL LOG SOC SIEM</h1>

{% for i in data %}
<div class="card">
    <p><b>ID:</b> {{i.id}}</p>
    <p><b>Attack:</b> {{i.attack}}</p>
    <p><b>Score:</b> {{i.score}}</p>
    <p><b>Severity:</b> {{i.severity}}</p>
    <p><b>Source:</b> {{i.source_ip}}</p>
    <p><b>Analysis:</b> {{i.analysis}}</p>
    <p><b>Raw:</b> {{i.raw_log}}</p>
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
# MAIN ENGINE
# -----------------------------
if __name__ == "__main__":
    print("[*] Reading real system logs...")

    incidents = build_incidents()

    print(f"[+] New incidents detected: {len(incidents)}")

    print("🔥 Starting Dashboard -> http://127.0.0.1:5000")
    app.run(debug=False)
