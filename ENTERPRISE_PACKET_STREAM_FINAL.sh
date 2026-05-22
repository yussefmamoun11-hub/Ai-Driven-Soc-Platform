#!/bin/bash
set -e

PROJECT="/home/youssef-amr/soc_project"
cd "$PROJECT"

TS=$(date +"%Y%m%d_%H%M%S")
BACKUP="/home/youssef-amr/soc_project_BACKUP_PACKET_STREAM_$TS"
cp -r "$PROJECT" "$BACKUP"

cat > packet_stream_server.py <<'PY'
#!/usr/bin/env python3
import json, re, time, threading
from pathlib import Path
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PROJECT = Path("/home/youssef-amr/soc_project")
AUTH_LOG = Path("/var/log/auth.log")
PORT = 9101

packets = []
version = 0

def parse_line(line):
    if "Failed password" not in line and "Accepted password" not in line:
        return None

    ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    user = re.search(r"for (invalid user )?([A-Za-z0-9_.-]+)", line)

    if not ip:
        return None

    src = ip.group(1)
    username = user.group(2) if user else "unknown"
    success = "Accepted password" in line

    return {
        "no": 0,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "source": src,
        "src_ip": src,
        "destination": "Ubuntu Host",
        "dst_ip": "Ubuntu Host",
        "proto": "SSH",
        "len": 84,
        "info": ("Successful" if success else "Failed") + f" SSH login for {username} from {src}",
        "severity": "CRITICAL" if success else "HIGH"
    }

def save_state():
    for folder in ["data", "outputs", "final_attack_snapshot"]:
        d = PROJECT / folder
        d.mkdir(exist_ok=True)
        (d / "network_packets.json").write_text(json.dumps(packets[-50:], indent=2))

def monitor_auth():
    global packets, version

    AUTH_LOG.touch(exist_ok=True)
    with AUTH_LOG.open("r", errors="ignore") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            pkt = parse_line(line)
            if pkt:
                pkt["no"] = len(packets) + 1
                packets.append(pkt)
                packets = packets[-50:]
                version += 1
                save_state()
                print(f"PACKET LIVE {pkt['src_ip']} {pkt['info']}", flush=True)

class Handler(BaseHTTPRequestHandler):
    def _headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def do_GET(self):
        global version

        if self.path.startswith("/api/packets"):
            self._headers()
            self.wfile.write(json.dumps({
                "version": version,
                "packets": packets[-50:]
            }).encode())
            return

        if self.path.startswith("/stream"):
            self._headers("text/event-stream")
            last = -1

            while True:
                if version != last:
                    last = version
                    data = json.dumps({
                        "version": version,
                        "packets": packets[-50:]
                    })
                    try:
                        self.wfile.write(f"data: {data}\n\n".encode())
                        self.wfile.flush()
                    except:
                        break
                time.sleep(0.2)
            return

        self.send_response(404)
        self.end_headers()

threading.Thread(target=monitor_auth, daemon=True).start()
print(f"Packet Stream Server running on :{PORT}", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
PY

chmod +x packet_stream_server.py

cat > packet_stream_dashboard_patch.js <<'JS'
(function(){
  console.log("ENTERPRISE PACKET STREAM ACTIVE");

  const API = "http://192.168.1.17:9101";

  function findPacketPanel(){
    const nodes = [...document.querySelectorAll("div,section,main,article")];
    return nodes
      .filter(n => {
        const t = (n.innerText || "").toUpperCase();
        return t.includes("PACKET CAPTURE") && t.includes("TIMESTAMP") && t.includes("SOURCE");
      })
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function render(packets){
    if(!packets || !packets.length) return;

    const panel = findPacketPanel();
    if(!panel) return;

    const ip = packets[packets.length - 1].src_ip || packets[packets.length - 1].source;

    panel.querySelectorAll("*").forEach(el=>{
      if(!el.children.length && el.textContent.includes("FILTER:")){
        el.textContent = "FILTER: ip.src == " + ip;
      }
    });

    let live = document.getElementById("enterprise-live-packet-stream");
    if(!live){
      live = document.createElement("div");
      live.id = "enterprise-live-packet-stream";
      live.style.cssText = `
        margin-top:8px;
        padding:8px;
        border:1px solid rgba(0,234,255,.45);
        background:#050d18;
        position:relative;
        z-index:99999;
      `;
      panel.prepend(live);
    }

    live.innerHTML = `
      <div style="color:#00eaff;font-weight:bold;letter-spacing:3px;margin-bottom:6px;">
        LIVE PACKET STREAM · ${ip}
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:12px;color:#9fb3d9;">
        <thead>
          <tr style="color:#6f7fa4;letter-spacing:2px;">
            <th>No.</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Packet Info</th>
          </tr>
        </thead>
        <tbody>
          ${packets.slice(-12).map((p,i)=>`
            <tr>
              <td>${i+1}</td>
              <td>${p.timestamp || ""}</td>
              <td style="color:#00eaff">${p.src_ip || p.source || ""}</td>
              <td>${p.destination || "Ubuntu Host"}</td>
              <td style="color:#ffbf00">${p.proto || "SSH"}</td>
              <td>${p.len || 84}</td>
              <td>${p.info || "SSH event"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function start(){
    try{
      const es = new EventSource(API + "/stream");
      es.onmessage = e => {
        const data = JSON.parse(e.data);
        if(data.packets && data.packets.length){
          localStorage.setItem("SOC_PACKET_STREAM_LAST", JSON.stringify(data.packets));
          render(data.packets);
        }
      };
      es.onerror = () => fallback();
    }catch(e){
      fallback();
    }
  }

  async function fallback(){
    try{
      const r = await fetch(API + "/api/packets?t=" + Date.now(), {cache:"no-store"});
      const d = await r.json();
      if(d.packets && d.packets.length){
        localStorage.setItem("SOC_PACKET_STREAM_LAST", JSON.stringify(d.packets));
        render(d.packets);
      }else{
        const old = JSON.parse(localStorage.getItem("SOC_PACKET_STREAM_LAST") || "[]");
        render(old);
      }
    }catch(e){
      const old = JSON.parse(localStorage.getItem("SOC_PACKET_STREAM_LAST") || "[]");
      render(old);
    }
  }

  start();
  setInterval(fallback, 2000);
})();
JS

for f in index.html frontend/index.html monitor/frontend/index.html; do
  [ -f "$f" ] || continue
  dir=$(dirname "$f")
  [ "$dir" != "." ] && cp packet_stream_dashboard_patch.js "$dir/packet_stream_dashboard_patch.js"

  if ! grep -q "packet_stream_dashboard_patch.js" "$f"; then
    sed -i 's#</body>#<script src="packet_stream_dashboard_patch.js"></script>\n</body>#i' "$f"
  fi
done

sudo tee /etc/systemd/system/soc-packet-stream.service > /dev/null <<SERVICE
[Unit]
Description=Enterprise SOC Packet Capture Stream
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT
ExecStart=/usr/bin/python3 $PROJECT/packet_stream_server.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable soc-packet-stream.service
sudo systemctl restart soc-packet-stream.service

echo "DONE"
echo "Backup: $BACKUP"
echo "Now open dashboard and press Ctrl+F5"
echo "Console must show: ENTERPRISE PACKET STREAM ACTIVE"
echo "Service check: sudo systemctl status soc-packet-stream.service"
