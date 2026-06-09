#!/usr/bin/env bash
set -e
cd /home/youssef-amr/soc_project
source venv/bin/activate

OLD_PID=$(sudo ss -ltnp | grep ':8080' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)

echo "Current 8080 PID: ${OLD_PID:-none}"

if [ -n "$OLD_PID" ]; then
  echo "Stopping old 8080 process..."
  sudo kill "$OLD_PID" || true
  sleep 1
fi

echo "Starting unified 8080 live SIEM..."
nohup python3 soc_unified_8080_live.py > runtime/unified_8080_live.log 2>&1 &

sleep 2
sudo ss -ltnp | grep ':8080'
tail -30 runtime/unified_8080_live.log
