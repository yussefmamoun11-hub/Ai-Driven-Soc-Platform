#!/usr/bin/env python3
import json, re, time, threading
from pathlib import Path
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PROJECT = Path("/home/youssef-amr/soc_project")
AUTH_LOG = Path("/var/log/auth.log")
PORT = 9101

packets = []
version = 0

def parse_line(line):
    if "Failed password" not in line and "Accepted password" not in line:
        return None

    ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    user = re.search(r"for (invalid user )?([A-Za-z0-9_.-]+)", line)

    if not ip:
        return None

    src = ip.group(1)
    username = user.group(2) if user else "unknown"
    success = "Accepted password" in line

    return {
        "no": 0,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "source": src,
        "src_ip": src,
        "destination": "Ubuntu Host",
        "dst_ip": "Ubuntu Host",
        "proto": "SSH",
        "len": 84,
        "info": ("Successful" if success else "Failed") + f" SSH login for {username} from {src}",
        "severity": "CRITICAL" if success else "HIGH"
    }

def save_state():
    for folder in ["data", "outputs", "final_attack_snapshot"]:
        d = PROJECT / folder
        d.mkdir(exist_ok=True)
        (d / "network_packets.json").write_text(json.dumps(packets[-50:], indent=2))

def monitor_auth():
    global packets, version

    AUTH_LOG.touch(exist_ok=True)
    with AUTH_LOG.open("r", errors="ignore") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            pkt = parse_line(line)
            if pkt:
                pkt["no"] = len(packets) + 1
                packets.append(pkt)
                packets = packets[-50:]
                version += 1
                save_state()
                print(f"PACKET LIVE {pkt['src_ip']} {pkt['info']}", flush=True)

class Handler(BaseHTTPRequestHandler):
    def _headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def do_GET(self):
        global version

        if self.path.startswith("/api/packets"):
            self._headers()
            self.wfile.write(json.dumps({
                "version": version,
                "packets": packets[-50:]
            }).encode())
            return

        if self.path.startswith("/stream"):
            self._headers("text/event-stream")
            last = -1

            while True:
                if version != last:
                    last = version
                    data = json.dumps({
                        "version": version,
                        "packets": packets[-50:]
                    })
                    try:
                        self.wfile.write(f"data: {data}\n\n".encode())
                        self.wfile.flush()
                    except:
                        break
                time.sleep(0.2)
            return

        self.send_response(404)
        self.end_headers()

threading.Thread(target=monitor_auth, daemon=True).start()
print(f"Packet Stream Server running on :{PORT}", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
