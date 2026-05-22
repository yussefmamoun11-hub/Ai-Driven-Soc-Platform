#!/bin/bash
set -e

cd /home/youssef-amr/soc_project

TS=$(date +"%Y%m%d_%H%M%S")
BACKUP="/home/youssef-amr/soc_project_BACKUP_STICKY_$TS"
cp -r /home/youssef-amr/soc_project "$BACKUP"

echo "Backup: $BACKUP"

cat > sticky_final_state.js <<'JS'
(function () {
  console.log("✅ Sticky Final State Enabled");

  const CACHE_KEY = "SOC_LAST_FINAL_STATE";

  function saveState(key, data) {
    if (!data) return data;
    const valid =
      (Array.isArray(data) && data.length > 0) ||
      (!Array.isArray(data) && typeof data === "object" && Object.keys(data).length > 0);

    if (valid) {
      const cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}");
      cache[key] = data;
      localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
    }
    return data;
  }

  function loadState(key) {
    const cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}");
    return cache[key] || null;
  }

  const originalFetch = window.fetch;

  window.fetch = async function (url, options) {
    const response = await originalFetch(url, options);
    const clone = response.clone();

    if (String(url).includes(".json")) {
      try {
        const data = await clone.json();
        const key = String(url).split("?")[0];

        const isEmptyArray = Array.isArray(data) && data.length === 0;
        const isEmptyObject =
          !Array.isArray(data) &&
          typeof data === "object" &&
          data &&
          Object.keys(data).length === 0;

        const isResetState =
          JSON.stringify(data).includes('"attempts":0') ||
          JSON.stringify(data).includes('"alerts":0') ||
          JSON.stringify(data).includes('"MONITORING"') ||
          JSON.stringify(data).includes('"waiting"') ||
          JSON.stringify(data).includes('"No confirmed attack yet"');

        if (isEmptyArray || isEmptyObject || isResetState) {
          const cached = loadState(key);
          if (cached) {
            return new Response(JSON.stringify(cached), {
              status: 200,
              headers: { "Content-Type": "application/json" }
            });
          }
        }

        saveState(key, data);
      } catch (e) {}
    }

    return response;
  };
})();
JS

for f in index.html frontend/index.html monitor/frontend/index.html; do
  [ -f "$f" ] || continue

  cp sticky_final_state.js "$(dirname "$f")/sticky_final_state.js"

  if ! grep -q "sticky_final_state.js" "$f"; then
    sed -i 's#<script src="live_all_panels_controller.js"></script>#<script src="sticky_final_state.js"></script>\n<script src="live_all_panels_controller.js"></script>#g' "$f"
    if ! grep -q "sticky_final_state.js" "$f"; then
      sed -i 's#</body>#<script src="sticky_final_state.js"></script>\n</body>#i' "$f"
    fi
  fi
done

sudo systemctl restart soc-live-panels.service

echo "✅ Sticky Final State installed."
echo "افتح الداشبورد واعمل Ctrl+F5"
