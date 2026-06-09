#!/usr/bin/env bash
set -e
cd /home/youssef-amr/soc_project

mkdir -p data outputs runtime

cat > soc_live_panels_stable_writer.py <<'PY'
#!/usr/bin/env python3
import os, re, json, time, datetime
from pathlib import Path
from collections import defaultdict, deque

ROOT = Path("/home/youssef-amr/soc_project")
AUTH = Path("/var/log/auth.log")

DATA = ROOT / "data"
OUT = ROOT / "outputs"

PACKETS = DATA / "network_packets.json"
ALERTS = OUT / "alerts.json"
CORR = OUT / "correlation.json"
PRIV = OUT / "privilege_activity.json"
SSH = OUT / "ssh_auth_activity.json"
SUCCESS = OUT / "successful_logins.json"

CACHE = {
    "packets": deque(maxlen=80),
    "alerts": deque(maxlen=80),
    "corr": deque(maxlen=80),
    "ssh": deque(maxlen=80),
    "success": deque(maxlen=40),
    "priv": deque(maxlen=50),
}

seen = set()
failed_by_ip = defaultdict(list)

def now():
    return datetime.datetime.now().isoformat(timespec="seconds")

def atomic_write(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
    tmp.replace(path)

def ip_from(line):
    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    return m.group(1) if m else "-"

def user_from(line):
    m = re.search(r"for invalid user ([A-Za-z0-9_.-]+)", line)
    if m: return m.group(1)
    m = re.search(r"for ([A-Za-z0-9_.-]+)", line)
    return m.group(1) if m else "-"

def process(line):
    if not any(x in line for x in ["Failed password", "Accepted password", "sudo", "session opened", "session closed"]):
        return

    ts = now()
    ip = ip_from(line)
    user = user_from(line)

    if "Failed password" in line:
        failed_by_ip[ip].append(time.time())
        attempts = len([x for x in failed_by_ip[ip] if time.time() - x <= 120])

        packet = {
            "timestamp": ts,
            "source": ip,
            "src_ip": ip,
            "destination": "Ubuntu Host",
            "proto": "SSH",
            "len": 84,
            "info": f"Failed SSH authentication attempt for {user}",
            "raw": line.strip()
        }
        CACHE["packets"].append(packet)
        CACHE["ssh"].append(packet)

        alert = {
            "time": ts,
            "id": "INC-002",
            "severity": "HIGH" if attempts >= 5 else "MED",
            "attack": "SSH Brute Force",
            "source_ip": ip,
            "user": user,
            "attempts": attempts,
            "description": f"Failed SSH login detected from {ip}"
        }
        CACHE["alerts"].append(alert)

        corr = {
            "time": ts,
            "source_ip": ip,
            "destination": "Ubuntu Host",
            "event_description": f"Failed SSH logins escalating — {attempts} attempts",
            "severity": "HIGH" if attempts >= 5 else "MED",
            "mitre": "T1110"
        }
        CACHE["corr"].append(corr)

    elif "Accepted password" in line:
        event = {
            "time": ts,
            "source_ip": ip,
            "user": user,
            "status": "SUCCESS",
            "description": f"Successful SSH login for {user} from {ip}",
            "raw": line.strip()
        }
        CACHE["success"].append(event)
        CACHE["ssh"].append(event)
        CACHE["packets"].append({
            "timestamp": ts,
            "source": ip,
            "src_ip": ip,
            "destination": "Ubuntu Host",
            "proto": "SSH",
            "len": 84,
            "info": f"Successful SSH login for {user}",
            "raw": line.strip()
        })
        CACHE["corr"].append({
            "time": ts,
            "source_ip": ip,
            "destination": "Ubuntu Host",
            "event_description": "Successful login after authentication activity",
            "severity": "CRITICAL",
            "mitre": "T1078"
        })

    elif "sudo" in line:
        CACHE["priv"].append({
            "time": ts,
            "source_ip": ip,
            "user": user,
            "severity": "HIGH",
            "activity": "Privilege activity / sudo event",
            "mitre": "T1548",
            "raw": line.strip()
        })

def flush():
    atomic_write(PACKETS, list(CACHE["packets"]))
    atomic_write(ALERTS, list(CACHE["alerts"]))
    atomic_write(CORR, list(CACHE["corr"]))
    atomic_write(PRIV, list(CACHE["priv"]))
    atomic_write(SSH, list(CACHE["ssh"]))
    atomic_write(SUCCESS, list(CACHE["success"]))

def load_existing():
    mapping = [
        (PACKETS, "packets"), (ALERTS, "alerts"), (CORR, "corr"),
        (PRIV, "priv"), (SSH, "ssh"), (SUCCESS, "success")
    ]
    for path, key in mapping:
        try:
            if path.exists():
                data = json.loads(path.read_text())
                if isinstance(data, list):
                    for x in data[-60:]:
                        CACHE[key].append(x)
        except Exception:
            pass

def main():
    load_existing()
    flush()
    pos = 0

    if AUTH.exists():
        pos = max(0, AUTH.stat().st_size - 200000)

    print("[STABLE PANELS] running. No frontend changes. No ports.", flush=True)

    while True:
        try:
            if AUTH.exists():
                size = AUTH.stat().st_size
                if size < pos:
                    pos = 0

                with AUTH.open("r", errors="ignore") as f:
                    f.seek(pos)
                    lines = f.readlines()
                    pos = f.tell()

                for line in lines:
                    key = line.strip()
                    if key and key not in seen:
                        seen.add(key)
                        process(line)

                flush()

        except Exception as e:
            print("[STABLE PANELS ERROR]", e, flush=True)

        time.sleep(0.3)

if __name__ == "__main__":
    main()
PY

chmod +x soc_live_panels_stable_writer.py

mkdir -p runtime
sudo chown -R $USER:$USER runtime data outputs

pkill -f soc_live_panels_stable_writer.py 2>/dev/null || true

nohup python3 soc_live_panels_stable_writer.py > runtime/stable_panels.log 2>&1 &

echo "✅ Stable panels writer started"
tail -20 runtime/stable_panels.log
