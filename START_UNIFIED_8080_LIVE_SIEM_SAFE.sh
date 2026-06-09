#!/usr/bin/env bash
set -e

PROJECT="/home/youssef-amr/soc_project"
cd "$PROJECT"

# Activate virtual environment
source venv/bin/activate

echo "[*] Checking for processes on 8080..."
PIDS=$(sudo ss -ltnp | grep ':8080' | awk -F'pid=' '{print $2}' | awk -F',' '{print $1}')
if [ -n "$PIDS" ]; then
  echo "[!] Found existing processes on 8080: $PIDS"
  for pid in $PIDS; do
    echo "Killing PID $pid ..."
    sudo kill -9 $pid
  done
  sleep 1
fi

# Ensure runtime folder exists with correct permissions
mkdir -p runtime
sudo chown -R $USER:$USER runtime
chmod 755 runtime

# Start Unified Live SIEM
echo "[*] Starting Unified SOC/SIEM on 8080..."
nohup python3 soc_unified_8080_live.py > runtime/unified_8080_live.log 2>&1 &

sleep 2
echo "[*] Current 8080 listeners:"
sudo ss -ltnp | grep ':8080'

echo "[*] Last 30 lines of log:"
tail -30 runtime/unified_8080_live.log

echo ""
echo "✅ Unified SOC/SIEM should now be running live on http://0.0.0.0:8080"
