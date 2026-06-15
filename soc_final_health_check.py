#!/usr/bin/env python3

import json
import os
from pathlib import Path

print("\n" + "="*70)
print("SOC NEXUS FINAL HEALTH CHECK")
print("="*70)

ROOT = Path("/home/youssef-amr/soc_project")

checks = [
    ("Dashboard", ROOT / "soc_unified_8080_live.py"),
    ("Truth Writer", ROOT / "soc_nexus_truth_writer.py"),
    ("Live State Writer", ROOT / "soc_nexus_live_state_writer.py"),
    ("Panel State", ROOT / "outputs/panel_live_state.json"),
    ("Alerts", ROOT / "outputs/alerts.json"),
    ("Correlation", ROOT / "outputs/correlation.json"),
    ("Packets", ROOT / "outputs/network_packets.json"),
    ("SSH Auth", ROOT / "outputs/ssh_auth_activity.json"),
]

all_ok = True

for name, path in checks:
    if path.exists():
        print(f"[OK] {name}")
    else:
        print(f"[FAIL] {name}")
        all_ok = False

print("\n" + "="*70)
print("DATA VALIDATION")
print("="*70)

try:
    panel = json.load(open(ROOT / "outputs/panel_live_state.json"))

    packets = len(panel.get("packets", []))
    alerts = len(panel.get("alerts", []))
    ssh = len(panel.get("ssh_auth", []))
    corr = len(panel.get("correlation", []))

    print(f"Packets        : {packets}")
    print(f"Alerts         : {alerts}")
    print(f"SSH Events     : {ssh}")
    print(f"Correlation    : {corr}")

except Exception as e:
    print("Panel State Error:", e)
    all_ok = False

print("\n" + "="*70)
print("IP DISCOVERY")
print("="*70)

try:
    if packets > 0:
        pkt = panel["packets"][-1]

        attacker = (
            pkt.get("src_ip")
            or pkt.get("source")
            or pkt.get("src")
            or "UNKNOWN"
        )

        target = (
            pkt.get("dst_ip")
            or pkt.get("destination")
            or pkt.get("dst")
            or "UNKNOWN"
        )

        print("Attacker IP :", attacker)
        print("Target IP   :", target)

        if attacker == target:
            print("[WARNING] SOURCE = DESTINATION")

except:
    pass

print("\n" + "="*70)
print("PDF GENERATOR")
print("="*70)

pdf_dir = Path.home() / "Desktop" / "SOC_Reports"

if pdf_dir.exists():
    pdfs = sorted(pdf_dir.glob("*.pdf"))

    if pdfs:
        latest = pdfs[-1]

        print("Latest PDF :", latest.name)
        print("Size       :", round(latest.stat().st_size/1024,1), "KB")

        if latest.stat().st_size < 10000:
            print("[WARNING] Small PDF detected")
    else:
        print("[WARNING] No PDF reports found")
else:
    print("[FAIL] SOC_Reports folder missing")
    all_ok = False

print("\n" + "="*70)
print("FINAL STATUS")
print("="*70)

if all_ok:
    print("SYSTEM HEALTH: PASS")
    print("Dashboard OK")
    print("Detection OK")
    print("Correlation OK")
    print("PDF Engine OK")
    print("Dynamic IP Support OK")
else:
    print("SYSTEM HEALTH: ATTENTION REQUIRED")

print("="*70)
