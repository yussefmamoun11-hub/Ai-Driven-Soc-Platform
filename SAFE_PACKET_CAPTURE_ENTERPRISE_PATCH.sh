#!/bin/bash
set -e

cd /home/youssef-amr/soc_project

TS=$(date +"%Y%m%d_%H%M%S")
BACKUP="/home/youssef-amr/soc_project_BACKUP_SAFE_PACKET_$TS"
cp -r /home/youssef-amr/soc_project "$BACKUP"

echo "Backup saved: $BACKUP"

# انسخ الباتش بدون حذف أي حاجة قديمة
cp force_packet_capture_dom_v2.js soc_packet_enterprise_fix.js

cp soc_packet_enterprise_fix.js frontend/soc_packet_enterprise_fix.js 2>/dev/null || true
cp soc_packet_enterprise_fix.js monitor/frontend/soc_packet_enterprise_fix.js 2>/dev/null || true

# أضفه فقط لو مش موجود
for f in index.html frontend/index.html monitor/frontend/index.html; do
  [ -f "$f" ] || continue

  if ! grep -q "soc_packet_enterprise_fix.js" "$f"; then
    sed -i 's#</body>#<script src="soc_packet_enterprise_fix.js"></script>\n</body>#i' "$f"
    echo "patched $f"
  else
    echo "already patched $f"
  fi
done

echo "DONE SAFE PATCH"
echo "افتح الداشبورد واضغط Ctrl+F5"
