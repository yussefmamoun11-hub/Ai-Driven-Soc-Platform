#!/usr/bin/env python3
"""
SOC Detection Engine — Ubuntu Side
Task 3.1 → 3.5 + PDF Report Export
"""

import json, re, os, sys, time
from datetime import datetime
from collections import defaultdict

# PDF library
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

OUTPUT_DIR = "/home/youssef-amr/soc_project/outputs"
REPORT_DIR = os.path.join(OUTPUT_DIR, "reports")

AUTH_LOG = "/var/log/auth.log"
AUDIT_LOG = "/var/log/audit/audit.log"

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/", "/home/socdemo/.ssh/",
    "/bank_data/", "/tmp/flag.txt"
]

PRIV_COMMANDS = [
    "sudo", "su -", "chmod 777", "chown root",
    "passwd", "visudo", "usermod", "id", "whoami"
]

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# =========================
# PARSING
# =========================
def parse_auth_log():
    events = []
    if not os.path.exists(AUTH_LOG):
        return events

    for line in open(AUTH_LOG, "r", errors="ignore"):
        ts = datetime.now().isoformat()

        if "Failed password" in line:
            m = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                events.append({
                    "event_type": "failed_login",
                    "src_ip": m.group(1),
                    "severity": "low",
                    "timestamp": ts
                })

        elif "Accepted" in line:
            m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                events.append({
                    "event_type": "successful_login",
                    "src_ip": m.group(1),
                    "severity": "high",
                    "timestamp": ts
                })

    return events


def parse_auditd():
    events = []
    if not os.path.exists(AUDIT_LOG):
        return events

    for line in open(AUDIT_LOG, "r", errors="ignore"):
        ts = datetime.now().isoformat()

        for path in SENSITIVE_PATHS:
            if path in line:
                events.append({
                    "event_type": "sensitive_file_access",
                    "file_path": path,
                    "severity": "high",
                    "timestamp": ts
                })

        for cmd in PRIV_COMMANDS:
            if cmd in line:
                events.append({
                    "event_type": "privilege_abuse_attempt",
                    "command": cmd,
                    "severity": "critical",
                    "timestamp": ts
                })

    return events


# =========================
# NORMALIZE
# =========================
def normalize(events):
    for i, e in enumerate(events):
        e["seq"] = i + 1
    return events


# =========================
# SEVERITY
# =========================
def severity_ladder(events):
    ip_fails = defaultdict(int)

    for e in events:
        if e["event_type"] == "failed_login":
            ip_fails[e["src_ip"]] += 1

    attacker_ip = max(ip_fails, key=ip_fails.get) if ip_fails else None

    for e in events:
        ip = e.get("src_ip")

        if e["event_type"] == "failed_login":
            if ip_fails[ip] < 3:
                e["severity"] = "low"
            elif ip_fails[ip] < 10:
                e["severity"] = "medium"
            else:
                e["severity"] = "high"

        elif e["event_type"] == "successful_login":
            e["severity"] = "critical" if ip_fails.get(ip, 0) > 5 else "medium"

    return events, attacker_ip, ip_fails


# =========================
# AI ANALYSIS (rules-based)
# =========================
def ai_analysis(events, attacker_ip, ip_fails):
    fails = ip_fails.get(attacker_ip, 0) if attacker_ip else 0

    has_success = any(e["event_type"] == "successful_login" for e in events)
    has_priv = any(e["event_type"] == "privilege_abuse_attempt" for e in events)
    has_sensitive = any(e["event_type"] == "sensitive_file_access" for e in events)

    if has_priv and has_success:
        level = "CRITICAL"
        msg = "Full compromise detected"
    elif has_success:
        level = "HIGH"
        msg = "Unauthorized access suspected"
    elif fails > 10:
        level = "HIGH"
        msg = "Brute force attack"
    else:
        level = "LOW"
        msg = "Normal activity"

    return {
        "level": level,
        "message": msg,
        "attacker_ip": attacker_ip,
        "fails": fails,
        "timestamp": datetime.now().isoformat()
    }


# =========================
# PDF GENERATOR
# =========================
def generate_pdf(ai_result, events):
    filename = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(REPORT_DIR, filename)

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("SOC INCIDENT REPORT", styles["Title"]))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"Threat Level: {ai_result['level']}", styles["Normal"]))
    content.append(Paragraph(f"Attacker IP: {ai_result['attacker_ip']}", styles["Normal"]))
    content.append(Paragraph(f"Message: {ai_result['message']}", styles["Normal"]))

    content.append(Spacer(1, 10))
    content.append(Paragraph("Events:", styles["Heading2"]))

    for e in events[:20]:
        content.append(Paragraph(str(e), styles["Normal"]))

    doc.build(content)

    print(f"[✓] PDF generated: {path}")


# =========================
# PIPELINE
# =========================
def run():
    auth = parse_auth_log()
    audit = parse_auditd()

    events = normalize(auth + audit)
    events, attacker_ip, ip_fails = severity_ladder(events)
    ai = ai_analysis(events, attacker_ip, ip_fails)

    write_path = os.path.join(OUTPUT_DIR, "ai_analysis.json")
    with open(write_path, "w") as f:
        json.dump(ai, f, indent=2)

    generate_pdf(ai, events)

    print("\n=== RESULT ===")
    print(ai)


def write_json(data, name):
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# =========================
if __name__ == "__main__":
    run()
