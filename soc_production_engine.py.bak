import os
import time
import shutil
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


# =========================
# AI ANALYST REPORT
# =========================
def ai_analyze(events):
    attacker_ip = events.get("attacker_ip", "UNKNOWN")
    failed = events.get("failed", 0)
    success = events.get("success", 0)

    level = "LOW"
    if failed > 5:
        level = "MEDIUM"
    if failed > 10:
        level = "HIGH"
    if failed > 12:
        level = "CRITICAL"

    report = f"""
SOC INCIDENT REPORT - AI ANALYST

Threat Level: {level}
Attacker IP: {attacker_ip}

EXECUTIVE SUMMARY:
Automated attack detected targeting authentication system.

ANALYSIS:
- Failed Attempts: {failed}
- Successful Attempts: {success}

IMPACT:
Possible brute force / credential stuffing attempt.

MITRE:
T1110 - Brute Force

RECOMMENDATION:
Block IP {attacker_ip} immediately.
Enable rate limiting on SSH.
"""
    return report, level


# =========================
# CREATE PDF
# =========================
def create_pdf(text):
    out_dir = os.path.expanduser("~/soc_project/outputs/reports")
    os.makedirs(out_dir, exist_ok=True)

    filename = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(out_dir, filename)

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()

    content = []
    for line in text.split("\n"):
        content.append(Paragraph(line, styles["Normal"]))
        content.append(Spacer(1, 5))

    doc.build(content)
    return path


# =========================
# MOVE TO DESKTOP + OPEN
# =========================
def push_desktop(pdf_path):
    desktop = os.path.expanduser("~/Desktop")

    final_path = os.path.join(
        desktop,
        f"SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    shutil.copy(pdf_path, final_path)

    print("[✓] Desktop Report:", final_path)

    os.system(f'xdg-open "{final_path}"')
    os.system('notify-send "SOC ALERT" "Incident Report Generated"')

    return final_path


# =========================
# SIMULATED DETECTION ENGINE
# =========================
class AttackHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # هنا بنعمل simulation للهجوم
        fake_event = {
            "attacker_ip": "192.168.88.166",
            "failed": 14,
            "success": 1
        }

        print("[!] Attack detected!")

        report, level = ai_analyze(fake_event)
        pdf = create_pdf(report)
        push_desktop(pdf)


# =========================
# WATCH MODE (REALTIME)
# =========================
if __name__ == "__main__":
    path_to_watch = os.path.expanduser("~/soc_project/outputs")

    event_handler = AttackHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)

    observer.start()

    print("[SOC ENGINE] Running... Watching for attacks")

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
