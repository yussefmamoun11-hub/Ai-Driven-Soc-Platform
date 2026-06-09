#!/usr/bin/env python3
import re, json, time, datetime
from pathlib import Path
from collections import deque, defaultdict

ROOT = Path("/home/youssef-amr/soc_project")
AUTH_LOG = Path("/var/log/auth.log")
OUTPUTS = ROOT / "outputs"
DATA = ROOT / "data"

OUTPUTS.mkdir(exist_ok=True)
DATA.mkdir(exist_ok=True)

packets = deque(maxlen=80)
corr = deque(maxlen=40)
ssh = deque(maxlen=60)
success = deque(maxlen=20)
alerts = deque(maxlen=40)
failed = defaultdict(list)
seen = set()

def now(): return datetime.datetime.now().isoformat(timespec="seconds")

def ip(line):
    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    return m.group(1) if m else "-"

def user(line):
    m = re.search(r"for invalid user ([A-Za-z0-9_.-]+)", line)
    if m: return m.group(1)
    m = re.search(r"for ([A-Za-z0-9_.-]+)", line)
    return m.group(1) if m else "unknown"

def write(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False))

def process(line):
    t = now()
    src = ip(line)
    u = user(line)

    if "sshd[" not in line:  # filter out system commands
        return

    if "Failed password" in line:
        failed[src].append(time.time())
        attempts = len([x for x in failed[src] if time.time()-x <= 300])
        p = {
            "timestamp": t,
            "time": t,
            "source": src,
            "src_ip": src,
            "source_ip": src,
            "destination": "Ubuntu Host",
            "dst_ip": "Ubuntu Host",
            "proto": "SSH",
            "protocol": "SSH",
            "len": 84,
            "length": 84,
            "info": f"Failed SSH authentication attempt for {u}",
            "packet_info": f"Failed SSH authentication attempt for {u}",
            "raw": line.strip()
        }
        packets.append(p)
        ssh.append(p)
        corr.append({
            "time": t,
            "source_ip": src,
            "destination": "Ubuntu Host",
            "event_description": f"Failed SSH logins escalating — {attempts} attempts",
            "severity": "HIGH" if attempts >= 5 else "MED",
            "mitre": "T1110"
        })
        alerts.append({
            "time": t,
            "id": "INC-002",
            "attack": "SSH Brute Force",
            "source_ip": src,
            "user": u,
            "severity": "HIGH",
            "attempts": attempts
        })

    elif "Accepted password" in line:
        e = {
            "time": t,
            "source_ip": src,
            "source": src,
            "user": u,
            "status": "SUCCESS",
            "description": f"Successful SSH login for {u} from {src}",
            "info": f"Successful SSH login for {u}",
            "raw": line.strip()
        }
        success.append(e)
        ssh.append(e)
        packets.append({
            "timestamp": t,
            "time": t,
            "source": src,
            "src_ip": src,
            "source_ip": src,
            "destination": "Ubuntu Host",
            "dst_ip": "Ubuntu Host",
            "proto": "SSH",
            "protocol": "SSH",
            "len": 84,
            "length": 84,
            "info": f"Successful SSH login for {u}",
            "packet_info": f"Successful SSH login for {u}",
            "raw": line.strip()
        })
        corr.append({
            "time": t,
            "source_ip": src,
            "destination": "Ubuntu Host",
            "event_description": "Successful SSH login after brute-force activity",
            "severity": "CRITICAL",
            "mitre": "T1078"
        })

def flush():
    state = {
        "updated": now(),
        "packets": list(packets),
        "correlation": list(corr),
        "ssh_auth": list(ssh),
        "successful_logins": list(success),
        "alerts": list(alerts)
    }
    write(OUTPUTS / "panel_live_state.json", state)
    write(DATA / "network_packets.json", list(packets))
    write(OUTPUTS / "network_packets.json", list(packets))
    write(OUTPUTS / "correlation.json", list(corr))
    write(OUTPUTS / "ssh_auth_activity.json", list(ssh))
    write(OUTPUTS / "successful_logins.json", list(success))
    write(OUTPUTS / "alerts.json", list(alerts))

def main():
    # Initial load from auth.log
    pos = 0
    if AUTH_LOG.exists():
        pos = max(0, AUTH_LOG.stat().st_size - 50000)

    print("[LIVE PIPELINE] running...", flush=True)

    while True:
        try:
            if AUTH_LOG.exists():
                size = AUTH_LOG.stat().st_size
                if size < pos: pos = 0
                with AUTH_LOG.open("r", errors="ignore") as f:
                    f.seek(pos)
                    lines = f.readlines()
                    pos = f.tell()
                for line in lines:
                    k = line.strip()
                    if k and k not in seen:
                        seen.add(k)
                        process(line)
                flush()
        except Exception as e:
            print("[LIVE PIPELINE ERROR]", e, flush=True)
        time.sleep(0.25)

if __name__ == "__main__":
    main()
