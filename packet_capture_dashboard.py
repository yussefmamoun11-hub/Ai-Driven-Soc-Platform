#!/usr/bin/env python3
import re, json
from pathlib import Path
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

AUTH = Path("/var/log/auth.log")
PORT = 9102
LAST = []

def get_packets():
    global LAST
    rows = []
    if AUTH.exists():
        for line in AUTH.read_text(errors="ignore").splitlines()[-800:]:
            if "Failed password" not in line and "Accepted password" not in line:
                continue

            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user = re.search(r"for (invalid user )?([A-Za-z0-9_.-]+)", line)
            if not ip:
                continue

            src = ip.group(1)
            u = user.group(2) if user else "unknown"
            ok = "Accepted password" in line

            rows.append({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "source": src,
                "destination": "Ubuntu Host",
                "proto": "SSH",
                "len": 84,
                "info": ("Successful" if ok else "Failed") + f" SSH login for {u} from {src}"
            })

    if rows:
        LAST = rows[-50:]

    return LAST

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api"):
            data = get_packets()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b'''<!doctype html>
<html>
<head>
<title>Enterprise Packet Capture</title>
<style>
body{background:#050b14;color:#9fb3d9;font-family:Consolas,monospace;margin:0;padding:20px}
h1{color:#00eaff;letter-spacing:4px}
.badge{color:#00ff9c;border:1px solid #00ff9c;padding:5px 10px;border-radius:5px}
.filter{float:right;color:#7f8fad}
table{width:100%;border-collapse:collapse;margin-top:20px}
th{color:#607090;text-align:left;letter-spacing:3px;border-bottom:1px solid #14314a;padding:10px}
td{padding:10px;border-bottom:1px solid #101a28}
.src{color:#00eaff;font-weight:bold}
.proto{color:#ffbf00;border:1px solid #7a5700;padding:2px 8px;border-radius:4px}
.info{color:#dbe7ff}
</style>
</head>
<body>
<h1>PACKET CAPTURE · DEEP INSPECTION <span class="badge">LIVE</span></h1>
<div class="filter" id="filter">FILTER: waiting...</div>
<table>
<thead><tr><th>No.</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Packet Info</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<script>
let last=[];
async function tick(){
  try{
    const r=await fetch('/api?t='+Date.now());
    const d=await r.json();
    if(d.length) last=d;
  }catch(e){}
  if(!last.length)return;
  const ip=last[last.length-1].source;
  document.getElementById('filter').textContent='FILTER: ip.src == '+ip;
  document.getElementById('rows').innerHTML=last.slice(-20).map((p,i)=>`
    <tr>
      <td>${i+1}</td>
      <td>${p.timestamp}</td>
      <td class="src">${p.source}</td>
      <td>${p.destination}</td>
      <td><span class="proto">${p.proto}</span></td>
      <td>${p.len}</td>
      <td class="info">${p.info}</td>
    </tr>`).join('');
}
tick();
setInterval(tick,500);
</script>
</body>
</html>''')

print("Enterprise Packet Capture Dashboard running on :9102", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
