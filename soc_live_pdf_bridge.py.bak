import time
import os
import json
from datetime import datetime
from fpdf import FPDF

# =========================
# CONFIG
# =========================
DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")
LOG_SOURCE = "/tmp/soc_live_events.jsonl"  # هنفترض events هنا

# =========================
# PDF GENERATOR
# =========================
def generate_pdf(event):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="SOC LIVE INCIDENT REPORT", ln=True, align="C")
    pdf.ln(10)

    pdf.multi_cell(0, 10, f"""
Incident Time: {datetime.now().isoformat()}

Attack: {event.get('attack')}
Source IP: {event.get('source_ip')}
Target: {event.get('target')}
Severity: {event.get('severity')}
Score: {event.get('score', 'N/A')}

Analysis:
Live SOC Detection Engine Alert
""")

    filename = f"SOC_LIVE_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(DESKTOP, filename)

    pdf.output(path)

    print(f"[+] PDF GENERATED: {path}")


# =========================
# WATCHER
# =========================
def watch_events():
    print("[*] SOC PDF Bridge Running...")

    if not os.path.exists(LOG_SOURCE):
        open(LOG_SOURCE, "w").close()

    seen = set()

    while True:
        try:
            with open(LOG_SOURCE, "r") as f:
                lines = f.readlines()

            for line in lines:
                if line in seen:
                    continue
                seen.add(line)

                try:
                    event = json.loads(line.strip())
                except:
                    continue

                severity = event.get("severity", "").lower()

                if severity in ["high", "critical"]:
                    print("[!] ALERT DETECTED -> GENERATING PDF")
                    generate_pdf(event)

        except Exception as e:
            print("Error:", e)

        time.sleep(2)


# =========================
# SIMULATOR (for testing)
# =========================
def simulate_attack():
    sample_events = [
        {"attack": "ssh_bruteforce", "source_ip": "192.168.1.10", "target": "server", "severity": "high", "score": 88},
        {"attack": "port_scan", "source_ip": "10.0.0.5", "target": "gateway", "severity": "low", "score": 40},
        {"attack": "malware", "source_ip": "172.16.0.9", "target": "db", "severity": "critical", "score": 97},
    ]

    with open(LOG_SOURCE, "a") as f:
        for e in sample_events:
            f.write(json.dumps(e) + "\n")

    print("[*] Simulation events injected")


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    import threading

    simulate_attack()

    t = threading.Thread(target=watch_events, daemon=True)
    t.start()

    while True:
        time.sleep(10)
