#!/bin/bash
set -e

cd /home/youssef-amr/soc_project

TS=$(date +"%Y%m%d_%H%M%S")
BACKUP="/home/youssef-amr/soc_project_BACKUP_STICKY_V2_$TS"
cp -r /home/youssef-amr/soc_project "$BACKUP"

cat > sticky_final_state.js <<'JS'
(function () {
  console.log("Sticky Final State Enabled");

  const CACHE_KEY = "SOC_LAST_FINAL_STATE";
  const originalFetch = window.fetch;

  function valid(data) {
    return data && (
      (Array.isArray(data) && data.length > 0) ||
      (!Array.isArray(data) && typeof data === "object" && Object.keys(data).length > 0)
    );
  }

  function isBadState(data) {
    const s = JSON.stringify(data || {});
    return (
      s.includes('"attempts":0') ||
      s.includes('"alerts":0') ||
      s.includes('MONITORING') ||
      s.includes('waiting') ||
      s.includes('No confirmed attack yet')
    );
  }

  window.fetch = async function(url, options) {
    const res = await originalFetch(url, options);
    if (!String(url).includes(".json")) return res;

    try {
      const data = await res.clone().json();
      const key = String(url).split("?")[0];
      const cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}");

      if ((!valid(data) || isBadState(data)) && cache[key]) {
        return new Response(JSON.stringify(cache[key]), {
          status: 200,
          headers: {"Content-Type": "application/json"}
        });
      }

      if (valid(data) && !isBadState(data)) {
        cache[key] = data;
        localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
      }
    } catch(e) {}

    return res;
  };
})();
JS

for f in index.html frontend/index.html monitor/frontend/index.html; do
  [ -f "$f" ] || continue
  dir=$(dirname "$f")

  if [ "$dir" != "." ]; then
    cp sticky_final_state.js "$dir/sticky_final_state.js"
  fi

  if ! grep -q "sticky_final_state.js" "$f"; then
    sed -i 's#<script src="live_all_panels_controller.js"></script>#<script src="sticky_final_state.js"></script>\n<script src="live_all_panels_controller.js"></script>#g' "$f"
    if ! grep -q "sticky_final_state.js" "$f"; then
      sed -i 's#</body>#<script src="sticky_final_state.js"></script>\n</body>#i' "$f"
    fi
  fi
done

sudo systemctl restart soc-live-panels.service

echo "DONE"
echo "Backup: $BACKUP"
echo "افتح الداشبورد واضغط Ctrl+F5"
