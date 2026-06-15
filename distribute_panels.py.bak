#!/usr/bin/env python3
import json
from pathlib import Path
from collections import defaultdict

ROOT = Path("/home/youssef-amr/soc_project")
OUT = ROOT / "outputs"

# اقرأ البيانات الكاملة
panel = json.loads((OUT / "panel_live_state.json").read_text())

# توزيعات
search_first = []
full_login = []
deep_extraction = []
correlation_panel = panel.get("correlation", [])

seen_ips = set()

for pkt in panel.get("packets", []):
    deep_extraction.append(pkt)
    ip = pkt.get("src_ip")
    if ip and ip not in seen_ips:
        search_first.append(pkt)
        seen_ips.add(ip)

for login in panel.get("successful_logins", []):
    full_login.append(login)
    deep_extraction.append(login)

# اكتب كل ملف جديد
(OUT / "panel_search_first.json").write_text(json.dumps(search_first, indent=2))
(OUT / "panel_full_login.json").write_text(json.dumps(full_login, indent=2))
(OUT / "panel_deep_extraction.json").write_text(json.dumps(deep_extraction, indent=2))
(OUT / "panel_correlation.json").write_text(json.dumps(correlation_panel, indent=2))

print("✅ Panels distributed successfully")
