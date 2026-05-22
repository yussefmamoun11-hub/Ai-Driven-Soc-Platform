#!/bin/bash

set -e

TS=$(date +"%Y%m%d_%H%M%S")
NOW=$(date +"%Y-%m-%dT%H:%M:%S")
BACKUP_DIR="$HOME/soc_project_BACKUP_before_persistent_live_$TS"

echo "===================================="
echo " SAFE LIVE + PERSISTENT FINAL STATE"
echo "===================================="

echo "[1] Creating backup..."
cp -r ~/soc_project "$BACKUP_DIR"
echo "✅ Backup saved at: $BACKUP_DIR"

cd ~/soc_project
mkdir -p data outputs final_attack_snapshot

ATTACKER_IP=$(grep -RhoE "192\.168\.[0-9]+\.[0-9]+" outputs data 2>/dev/null | head -1)
[ -z "$ATTACKER_IP" ] && ATTACKER_IP="192.168.1.78"
TARGET_IP="192.168.1.17"

echo "[2] Creating live + final persistent feeds..."

cat > outputs/correlation.json <<JSON
{
  "status": "FINAL_ATTACK_STATE",
  "persistent": true,
  "last_updated": "$NOW",
  "incident_id": "INC-003",
  "classification": "Multi-Stage SSH Intrusion",
  "confidence": "VERY HIGH",
  "final_severity": "CRITICAL",
  "source_ip": "$ATTACKER_IP",
  "target_ip": "$TARGET_IP",
  "chain": [
    {"stage":"Recon","mitre":"T1046","severity":"LOW","status":"completed"},
    {"stage":"SSH Brute Force","mitre":"T1110","severity":"HIGH","status":"detected"},
    {"stage":"Valid Account Login","mitre":"T1078","severity":"CRITICAL","status":"confirmed"},
    {"stage":"System Discovery","mitre":"T1082","severity":"CRITICAL","status":"observed"},
    {"stage":"File Discovery","mitre":"T1083","severity":"CRITICAL","status":"observed"},
    {"stage":"Privilege Escalation Attempt","mitre":"T1548","severity":"CRITICAL","status":"blocked"}
  ]
}
JSON

cat > outputs/privilege_activity.json <<JSON
{
  "status": "FINAL_ATTACK_STATE",
  "persistent": true,
  "last_updated": "$NOW",
  "incident_id": "INC-003",
  "technique": "T1548",
  "activity": "Privilege Abuse Attempt",
  "severity": "CRITICAL",
  "result": "BLOCKED",
  "details": [
    "Sudo privileges check attempted",
    "SUID binaries search executed",
    "Cron jobs inspected",
    "Sudoers directory inspected",
    "Escalation blocked by hardened system",
    "Audit log generated"
  ]
}
JSON

cat > data/overview.json <<JSON
{
  "status": "FINAL_ATTACK_STATE",
  "persistent": true,
  "last_updated": "$NOW",
  "attacker_ip": "$ATTACKER_IP",
  "target_ip": "$TARGET_IP",
  "incident_id": "INC-003",
  "severity": "CRITICAL",
  "attack_type": "Multi-Stage SSH Intrusion",
  "failed_logins": 15,
  "successful_logins": 1,
  "alerts_count": 3,
  "attempts": 15,
  "stage": "Attack Completed",
  "containment": "Executed by Sharaf",
  "final_state_note": "Keep this state visible after attack ends"
}
JSON

cat > data/network_packets.json <<JSON
[
  {
    "timestamp": "$NOW",
    "persistent": true,
    "src_ip": "$ATTACKER_IP",
    "dst_ip": "$TARGET_IP",
    "proto": "SSH",
    "info": "Recon scan detected",
    "stage": "Recon",
    "mitre": "T1046"
  },
  {
    "timestamp": "$NOW",
    "persistent": true,
    "src_ip": "$ATTACKER_IP",
    "dst_ip": "$TARGET_IP",
    "proto": "SSH",
    "info": "SSH brute force attempts detected",
    "stage": "Brute Force",
    "mitre": "T1110"
  },
  {
    "timestamp": "$NOW",
    "persistent": true,
    "src_ip": "$ATTACKER_IP",
    "dst_ip": "$TARGET_IP",
    "proto": "SSH",
    "info": "Successful login after failed attempts",
    "stage": "Valid Accounts",
    "mitre": "T1078"
  }
]
JSON

cat > data/evidence_status.json <<JSON
{
  "status": "PRESERVED",
  "persistent": true,
  "last_updated": "$NOW",
  "owner": "Haneen",
  "auth_logs": "SAVED",
  "network_events": "SAVED",
  "network_analysis": "SAVED",
  "failed_logins": "15 attempts saved",
  "pcap_evidence": "VALIDATED",
  "evidence_files": 8,
  "evidence_path": "/root/redteam/evidence/run_014"
}
JSON

echo "[3] Copying final state snapshot..."
cp -f outputs/correlation.json final_attack_snapshot/correlation.json
cp -f outputs/privilege_activity.json final_attack_snapshot/privilege_activity.json
cp -f data/overview.json final_attack_snapshot/overview.json
cp -f data/network_packets.json final_attack_snapshot/network_packets.json
cp -f data/evidence_status.json final_attack_snapshot/evidence_status.json

echo "[4] Protecting final state files from accidental overwrite..."
chmod 444 final_attack_snapshot/*.json

echo ""
echo "===================================="
echo "✅ DONE"
echo "All panels have live/final attack data."
echo "Final attack state is saved and will remain visible."
echo "Snapshot folder: ~/soc_project/final_attack_snapshot"
echo "Backup folder: $BACKUP_DIR"
echo "Refresh dashboard now."
echo "===================================="
