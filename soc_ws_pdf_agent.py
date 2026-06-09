import websocket
import json
import os
from fpdf import FPDF

SEEN_IDS = set()

WS_URL = "ws://127.0.0.1:9000/ws"


class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(200, 10, "SOC INCIDENT WRITEUP", ln=True, align="C")
        self.ln(5)


def generate_pdf(incident):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, f"ID: {incident['id']}", ln=True)
    pdf.cell(200, 10, f"Attack: {incident['attack']}", ln=True)
    pdf.cell(200, 10, f"Source IP: {incident['source_ip']}", ln=True)
    pdf.cell(200, 10, f"Score: {incident['score']}", ln=True)
    pdf.cell(200, 10, f"Severity: {incident['severity']}", ln=True)

    pdf.ln(5)
    pdf.multi_cell(0, 10, incident.get("analysis", ""))

    desktop = os.path.expanduser("~/Desktop")
    filename = f"{desktop}/SOC_Report_{incident['id']}.pdf"

    pdf.output(filename)

    print(f"[✓] PDF saved -> {filename}")


def on_message(ws, message):
    print("[RAW MESSAGE]:", message)
    
    try:
        data = json.loads(message)

        print("[PARSED]:", data)

        if "id" in data and data["id"] not in SEEN_IDS:
            SEEN_IDS.add(data["id"])
            generate_pdf(data)

    except Exception as e:
        print("Error parsing:", e)


def on_open(ws):
    print("[*] Connected to SOC WebSocket")


def run():
    ws = websocket.WebSocketApp(
        WS_URL,
        on_message=on_message,
        on_open=on_open
    )
    ws.run_forever()


if __name__ == "__main__":
    run()
