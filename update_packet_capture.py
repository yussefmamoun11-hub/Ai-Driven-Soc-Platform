#!/usr/bin/env python3
import json
import re
from pathlib import Path
from datetime import datetime

PROJECT = Path("/home/youssef-amr/soc_project")
DATA = PROJECT / "data"
OUTPUTS = PROJECT / "outputs"
SNAP = PROJECT / "final_attack_snapshot"

TARGET_IP = "192.168.1.17"
DEFAULT_ATTACKER = "192.168.1.78"

def ensure_dirs():
    for d in [DATA, OUTPUTS, SNAP]:
        d.mkdir(parents=True, exist_ok=True)

def get_attacker_ip():
    auth = Path("/var/log/auth.log")
    if auth.exists():
        lines = auth.read_text(errors="ignore").splitlines()[-500:]
        for line in reversed(lines):
            m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if m:
                ip = m.group(1)
                if ip != TARGET_IP:
                    return ip
    return DEFAULT_ATTACKER

def get_failed_attempts(ip):
    auth = Path("/var/log/auth.log")
    if not auth.exists():
        return 0
    text = auth.read_text(errors="ignore")
    return len(re.findall(rf'Failed password.*from {re.escape(ip)}', text))

def build_packets():
    now = datetime.now().isoformat(timespec="seconds")
    attacker = get_attacker_ip()
    attempts = max(get_failed_attempts(attacker), 1)

    packets = []
    for i in range(min(attempts, 50)):
        packets.append({
            "no": i + 1,
            "seq": i + 1,
            "id": i + 1,
            "timestamp": now,
            "time": now,
            "src_ip": attacker,
            "source_ip": attacker,
            "source": attacker,
            "attacker_ip": attacker,
            "dst_ip": "Ubuntu Host",
            "destination": "Ubuntu Host",
            "destination_ip": "Ubuntu Host",
            "proto": "SSH",
            "protocol": "SSH",
            "len": 84,
            "length": 84,
            "info": f"Failed SSH authentication attempt #{i+1}",
            "packet_info": f"Failed SSH authentication attempt #{i+1}"
        })
    return packets

def save_packets(packets):
    for path in [
        DATA / "network_packets.json",
        OUTPUTS / "network_packets.json",
        SNAP / "network_packets.json"
    ]:
        path.write_text(json.dumps(packets, indent=2))

def main():
    ensure_dirs()
    packets = build_packets()
    save_packets(packets)
    print(f"Updated Packet Capture with {len(packets)} packets")

if __name__ == "__main__":
    main()
