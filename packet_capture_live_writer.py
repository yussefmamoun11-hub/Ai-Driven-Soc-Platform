#!/usr/bin/env python3
import json, re
from pathlib import Path
from datetime import datetime

PROJECT = Path("/home/youssef-amr/soc_project")
AUTH = Path("/var/log/auth.log")
TARGET = "Ubuntu Host"

def parse():
    lines = AUTH.read_text(errors="ignore").splitlines()[-300:] if AUTH.exists() else []
    rows = []
    for line in lines:
        if "Failed password" not in line and "Accepted password" not in line:
            continue

        ipm = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        userm = re.search(r"for (invalid user )?([A-Za-z0-9_.-]+)", line)
        if not ipm:
            continue

        ip = ipm.group(1)
        user = userm.group(2) if userm else "unknown"
        status = "Successful SSH login" if "Accepted password" in line else "Failed SSH login"
        sev = "CRITICAL" if "Accepted password" in line else "HIGH"

        rows.append({
            "no": len(rows)+1,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "source": ip,
            "src_ip": ip,
            "source_ip": ip,
            "attacker_ip": ip,
            "destination": TARGET,
            "dst_ip": TARGET,
            "proto": "SSH",
            "protocol": "SSH",
            "len": 84,
            "info": f"{status} for {user} from {ip}",
            "packet_info": f"{status} for {user} from {ip}",
            "severity": sev
        })

    return rows[-12:] if rows else []

def main():
    packets = parse()
    if not packets:
        return

    for folder in ["data", "outputs", "final_attack_snapshot"]:
        d = PROJECT / folder
        d.mkdir(exist_ok=True)
        (d / "network_packets.json").write_text(json.dumps(packets, indent=2))

    print(f"PACKET_CAPTURE_UPDATED rows={len(packets)} attacker={packets[-1]['source']}")

if __name__ == "__main__":
    main()
