#!/bin/bash
set -e

PROJECT="/home/youssef-amr/soc_project"
cd "$PROJECT"

TS=$(date +"%Y%m%d_%H%M%S")
BACKUP="/home/youssef-amr/soc_project_BACKUP_PACKET_ENTERPRISE_$TS"
cp -r "$PROJECT" "$BACKUP"

cat > packet_capture_live_writer.py <<'PY'
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
PY

chmod +x packet_capture_live_writer.py

cat > packet_capture_live_service.sh <<'SH'
#!/bin/bash
cd /home/youssef-amr/soc_project || exit 1

python3 packet_capture_live_writer.py

inotifywait -m -e modify,close_write,create,move /var/log/auth.log 2>/dev/null |
while read line; do
  python3 packet_capture_live_writer.py
done
SH

chmod +x packet_capture_live_service.sh

cat > packet_capture_inline_patch.txt <<'JS'
<script>
(function(){
  console.log("ENTERPRISE PACKET CAPTURE LIVE ACTIVE");

  async function loadPackets(){
    const paths=[
      "/data/network_packets.json",
      "/outputs/network_packets.json",
      "/final_attack_snapshot/network_packets.json"
    ];
    for(const p of paths){
      try{
        const r=await fetch(p+"?t="+Date.now(),{cache:"no-store"});
        const d=await r.json();
        if(Array.isArray(d)&&d.length){
          localStorage.setItem("SOC_PACKET_FINAL_CACHE",JSON.stringify(d));
          return d;
        }
      }catch(e){}
    }
    try{return JSON.parse(localStorage.getItem("SOC_PACKET_FINAL_CACHE")||"[]");}
    catch(e){return [];}
  }

  function smallestPacketPanel(){
    const nodes=[...document.querySelectorAll("div,section,main,article")];
    return nodes
      .filter(x=>{
        const t=(x.innerText||"").toUpperCase();
        return t.includes("PACKET CAPTURE") && t.includes("TIMESTAMP") && t.includes("SOURCE");
      })
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function render(packets){
    if(!packets.length) return;

    const panel=smallestPacketPanel();
    if(!panel) return;

    const ip=packets[packets.length-1].src_ip || packets[packets.length-1].source || "192.168.1.78";

    panel.querySelectorAll("*").forEach(el=>{
      if(!el.children.length && el.textContent.includes("FILTER:")){
        el.textContent="FILTER: ip.src == "+ip;
      }
    });

    let box=panel.querySelector("#enterprisePacketLiveBox");
    if(!box){
      box=document.createElement("div");
      box.id="enterprisePacketLiveBox";
      box.style.cssText="margin-top:8px;border-top:1px solid rgba(0,255,255,.35);background:#07101dcc;position:relative;z-index:9999;";
      panel.appendChild(box);
    }

    box.innerHTML=`
      <div style="color:#00eaff;font-weight:bold;letter-spacing:3px;margin:6px 0;">
        LIVE PACKET CAPTURE · ${ip}
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:12px;color:#9fb3d9;">
        <thead>
          <tr style="color:#6f7fa4;letter-spacing:3px;">
            <th>No.</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Packet Info</th>
          </tr>
        </thead>
        <tbody>
          ${packets.slice(-12).map((p,i)=>`
            <tr>
              <td>${i+1}</td>
              <td>${p.timestamp||p.time||""}</td>
              <td style="color:#00eaff">${p.src_ip||p.source_ip||p.source||ip}</td>
              <td>${p.destination||p.dst_ip||"Ubuntu Host"}</td>
              <td><span style="color:#ffbf00;border:1px solid #8a5b00;padding:1px 6px;border-radius:4px;">${p.proto||p.protocol||"SSH"}</span></td>
              <td>${p.len||84}</td>
              <td>${p.info||p.packet_info||"SSH authentication event"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  async function tick(){
    render(await loadPackets());
  }

  tick();
  setInterval(tick,500);
})();
</script>
JS

for f in index.html frontend/index.html monitor/frontend/index.html; do
  [ -f "$f" ] || continue
  if ! grep -q "ENTERPRISE PACKET CAPTURE LIVE ACTIVE" "$f"; then
    sed -i '/<\/body>/e cat packet_capture_inline_patch.txt' "$f"
  fi
done

sudo tee /etc/systemd/system/soc-packet-capture-live.service > /dev/null <<SERVICE
[Unit]
Description=SOC Packet Capture Enterprise Live Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT
ExecStart=/bin/bash $PROJECT/packet_capture_live_service.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable soc-packet-capture-live.service
sudo systemctl restart soc-packet-capture-live.service

python3 packet_capture_live_writer.py || true

echo "DONE"
echo "Backup: $BACKUP"
echo "Now open dashboard and press Ctrl+F5"
echo "Check console: ENTERPRISE PACKET CAPTURE LIVE ACTIVE"
