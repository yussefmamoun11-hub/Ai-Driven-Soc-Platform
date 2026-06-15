#!/usr/bin/env python3
import os, re, json, time, threading, datetime
from collections import defaultdict, deque
from flask import Flask, jsonify, send_from_directory, request
from flask_socketio import SocketIO

ROOT = os.path.dirname(os.path.abspath(__file__))
AUTH_LOG = "/var/log/auth.log"
DB_FILE = os.path.join(ROOT, "real_siem_db.json")

app = Flask(__name__, static_folder=ROOT, static_url_path="")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

recent_failed = defaultdict(lambda: deque(maxlen=100))
seen_lines = deque(maxlen=3000)
last_packets = deque(maxlen=100)
last_events = deque(maxlen=200)
timeline = deque(maxlen=200)

def now():
    return datetime.datetime.now().isoformat(timespec="seconds")

def load_db():
    try:
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_db(data):
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("[DB ERROR]", e, flush=True)

def extract_ip(line):
    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if m: return m.group(1)
    m = re.search(r"\d+(?:\.\d+){3}", line)
    return m.group(0) if m else "unknown"

def extract_user(line):
    m = re.search(r"for invalid user ([A-Za-z0-9_.-]+)", line)
    if m: return m.group(1)
    m = re.search(r"for ([A-Za-z0-9_.-]+)", line)
    return m.group(1) if m else "unknown"

def classify(line):
    if "Failed password" in line:
        return "ssh_bruteforce_attempt", "HIGH", 90
    if "Accepted password" in line:
        return "ssh_login_success", "MEDIUM", 65
    if "sudo" in line:
        return "privilege_activity", "MEDIUM", 75
    return None, "LOW", 20

def build_packet(line, attack, ip):
    return {
        "timestamp": now(),
        "source": ip,
        "src_ip": ip,
        "destination": "Ubuntu Host",
        "dst_ip": "Ubuntu Host",
        "proto": "SYSLOG",
        "protocol": "SYSLOG",
        "len": 84,
        "info": line.strip()[:240],
        "raw": line.strip()
    }

def correlate(event):
    ip = event.get("source_ip", "unknown")
    t = time.time()

    if event["attack"] == "ssh_bruteforce_attempt":
        recent_failed[ip].append(t)
        hits = [x for x in recent_failed[ip] if t - x <= 60]
        if len(hits) >= 5:
            return {
                "time": now(),
                "type": "correlated_bruteforce",
                "source_ip": ip,
                "severity": "CRITICAL",
                "summary": f"{len(hits)} failed SSH attempts from {ip} within 60 seconds",
                "timeline": list(timeline)
            }

    return {
        "time": now(),
        "type": "single_event",
        "source_ip": ip,
        "severity": event.get("severity", "LOW"),
        "summary": event.get("analysis", "Security event observed"),
        "timeline": list(timeline)
    }

def emit_event(line):
    attack, severity, score = classify(line)
    if not attack:
        return

    ip = extract_ip(line)
    user = extract_user(line)

    event = {
        "id": "INC-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "time": now(),
        "attack": attack,
        "source_ip": ip,
        "target": "Ubuntu Host",
        "user": user,
        "score": score,
        "severity": "CRITICAL" if score >= 85 else severity,
        "analysis": f"Live security event detected: {attack} from {ip}",
        "raw_log": line.strip()
    }

    packet = build_packet(line, attack, ip)
    corr = correlate(event)

    last_events.append(event)
    last_packets.append(packet)
    timeline.append({"time": event["time"], "attack": attack, "source_ip": ip, "severity": event["severity"]})

    db = load_db()
    db.append(event)
    save_db(db)

    socketio.emit("soc_event", event)
    socketio.emit("packet_event", packet)
    socketio.emit("correlation_event", corr)

    print("[LIVE]", event["attack"], event["source_ip"], flush=True)

def authlog_watcher():
    print("[*] Live watcher started:", AUTH_LOG, flush=True)
    pos = 0
    while True:
        try:
            if not os.path.exists(AUTH_LOG):
                time.sleep(1)
                continue

            size = os.path.getsize(AUTH_LOG)
            if size < pos:
                pos = 0

            with open(AUTH_LOG, "r", errors="ignore") as f:
                f.seek(pos)
                lines = f.readlines()
                pos = f.tell()

            for line in lines:
                key = line.strip()
                if not key or key in seen_lines:
                    continue
                seen_lines.append(key)
                emit_event(line)

        except Exception as e:
            print("[WATCHER ERROR]", e, flush=True)

        time.sleep(0.2)

@app.route("/")
def index():
    return send_from_directory(ROOT, "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(ROOT, path)

@app.route("/api/live/events")
def api_events():
    return jsonify(list(last_events) or load_db())


@app.route("/api/live/packets")
def api_packets():
    import json
    from pathlib import Path

    pkt_file = Path("data/network_packets.json")

    try:
        data = json.loads(pkt_file.read_text(encoding="utf-8"))

        for row in data:
            row["proto"] = "SSH"
            row["protocol"] = "SSH"

        return jsonify(data)

    except Exception as e:
        return jsonify([])


@app.route("/api/live/correlation")
def api_corr():
    return jsonify(list(timeline))

@socketio.on("connect")
def connected():
    socketio.emit("soc_bootstrap", {
        "events": list(last_events) or load_db(),
        "packets": list(last_packets),
        "timeline": list(timeline)
    }, to=request.sid)

if __name__ == "__main__":
    threading.Thread(target=authlog_watcher, daemon=True).start()
    print("🔥 Unified SOC/SIEM running ONLY on http://0.0.0.0:8080", flush=True)
    socketio.run(app, host="0.0.0.0", port=8080, debug=False)


