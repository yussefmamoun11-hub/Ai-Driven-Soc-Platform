#!/usr/bin/env bash
set -e
cd /home/youssef-amr/soc_project

BKP="backups/stable_distributed_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BKP"
cp index.html "$BKP/index.html.bak"

pkill -f soc_nexus_live_state_writer.py 2>/dev/null || true
pkill -f soc_live_panels_stable_writer.py 2>/dev/null || true
pkill -f soc_ai_full_pipeline_live.py 2>/dev/null || true

cat > soc_panel_live_distributor.py <<'PY'
#!/usr/bin/env python3
import re,json,time,datetime
from pathlib import Path
from collections import deque,defaultdict

ROOT=Path("/home/youssef-amr/soc_project")
AUTH=Path("/var/log/auth.log")
OUT=ROOT/"outputs"; DATA=ROOT/"data"; RUNTIME=ROOT/"runtime"
OUT.mkdir(exist_ok=True); DATA.mkdir(exist_ok=True); RUNTIME.mkdir(exist_ok=True)

packets=deque(maxlen=60)
correlation=deque(maxlen=40)
ssh_auth=deque(maxlen=40)
successful=deque(maxlen=20)
alerts=deque(maxlen=20)
failed=defaultdict(int)
seen=set()

def ts(line):
    m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",line)
    return m.group(1) if m else datetime.datetime.now().isoformat(timespec="seconds")

def ip(line):
    m=re.search(r" from (\d+\.\d+\.\d+\.\d+) ",line)
    return m.group(1) if m else "-"

def user(line):
    m=re.search(r"for invalid user ([\w.-]+)",line)
    if m:return m.group(1)
    m=re.search(r"for ([\w.-]+) from ",line)
    return m.group(1) if m else "unknown"

def write(p,o):
    p.write_text(json.dumps(o,indent=2,ensure_ascii=False))

def process(line):
    if "sshd[" not in line: return
    if "Failed password" not in line and "Accepted password" not in line: return

    t=ts(line); src=ip(line); u=user(line); n=len(packets)+1

    if "Failed password" in line:
        failed[src]+=1
        info=f"Failed SSH authentication attempt for {u}"
        pkt={
          "no":n,"id":n,"seq":n,
          "timestamp":t,"time":t,
          "source":src,"src_ip":src,"source_ip":src,
          "destination":"Ubuntu Host","dst_ip":"Ubuntu Host",
          "proto":"SSH","protocol":"SSH",
          "len":84,"length":84,
          "user":u,
          "info":info,"packet_info":info,
          "raw":line.strip()
        }
        packets.append(pkt)
        ssh_auth.append(pkt)
        correlation.append({
          "time":t,
          "source_ip":src,
          "destination":"Ubuntu Host",
          "event_description":f"Failed SSH logins escalating — {failed[src]} attempts",
          "severity":"HIGH" if failed[src]>=5 else "MED",
          "mitre":"T1110"
        })
        alerts.append({
          "time":t,"id":"INC-002","attack":"SSH Brute Force",
          "source_ip":src,"user":u,"severity":"HIGH","attempts":failed[src]
        })

    if "Accepted password" in line:
        info=f"Successful SSH login for {u}"
        pkt={
          "no":n,"id":n,"seq":n,
          "timestamp":t,"time":t,
          "source":src,"src_ip":src,"source_ip":src,
          "destination":"Ubuntu Host","dst_ip":"Ubuntu Host",
          "proto":"SSH","protocol":"SSH",
          "len":84,"length":84,
          "user":u,
          "info":info,"packet_info":info,
          "raw":line.strip()
        }
        packets.append(pkt)
        successful.append({
          "time":t,"timestamp":t,
          "source_ip":src,"source":src,"src_ip":src,
          "user":u,"status":"SUCCESS",
          "description":f"Successful SSH login for {u} from {src}",
          "info":info,
          "raw":line.strip()
        })
        correlation.append({
          "time":t,
          "source_ip":src,
          "destination":"Ubuntu Host",
          "event_description":"Successful SSH login after brute-force activity",
          "severity":"CRITICAL",
          "mitre":"T1078"
        })

def flush():
    state={
      "updated":datetime.datetime.now().isoformat(timespec="seconds"),
      "packets":list(packets),
      "ssh_auth":list(ssh_auth),
      "successful_logins":list(successful),
      "correlation":list(correlation),
      "alerts":list(alerts)
    }
    write(OUT/"panel_live_state.json",state)
    write(DATA/"network_packets.json",list(packets))
    write(OUT/"network_packets.json",list(packets))
    write(OUT/"ssh_auth_activity.json",list(ssh_auth))
    write(OUT/"successful_logins.json",list(successful))
    write(OUT/"correlation.json",list(correlation))
    write(OUT/"alerts.json",list(alerts))

def main():
    if AUTH.exists():
        for line in AUTH.read_text(errors="ignore").splitlines()[-6000:]:
            k=line.strip()
            if k not in seen:
                seen.add(k); process(line)
    flush()
    pos=AUTH.stat().st_size if AUTH.exists() else 0
    print("[STABLE DISTRIBUTOR] running",flush=True)

    while True:
        try:
            changed=False
            if AUTH.exists():
                if AUTH.stat().st_size < pos: pos=0
                with AUTH.open("r",errors="ignore") as f:
                    f.seek(pos); lines=f.readlines(); pos=f.tell()
                for line in lines:
                    k=line.strip()
                    if k and k not in seen:
                        seen.add(k)
                        before=len(packets)+len(successful)
                        process(line)
                        if len(packets)+len(successful)!=before:
                            changed=True
                if changed: flush()
        except Exception as e:
            print("[ERR]",e,flush=True)
        time.sleep(.3)

if __name__=="__main__":
    main()
PY

cat > soc_nexus_stable_dom.js <<'JS'
(function(){
  console.log("[STABLE DISTRIBUTED PANELS ACTIVE]");
  let lastHash="", stable={};

  function g(o,ks,f="-"){
    for(const k of ks){
      if(o && o[k]!==undefined && o[k]!==null && o[k]!=="" && o[k]!=="undefined") return o[k];
    }
    return f;
  }

  function panel(name){
    const n=name.toUpperCase();
    return [...document.querySelectorAll("section,article,div")]
      .filter(e=>(e.innerText||"").toUpperCase().includes(n))
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function count(p,t){
    if(!p)return;
    const el=[...p.querySelectorAll("*")]
      .find(x=>!x.children.length && /^(0|\d+|\d+\s+EVENTS)$/i.test((x.innerText||"").trim()));
    if(el) el.innerText=t;
  }

  function drawPackets(rows){
    if(!rows || !rows.length)return;
    const p=panel("PACKET CAPTURE");
    if(!p)return;
    const tb=p.querySelector("tbody");
    if(!tb)return;

    const ip=g(rows[rows.length-1],["source","src_ip","source_ip"],"-");
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("FILTER:")){
        x.innerText="FILTER: ip.src == "+ip;
      }
    });

    tb.innerHTML=rows.slice(-15).map((x,i)=>`
      <tr>
        <td>${g(x,["no","seq","id"],i+1)}</td>
        <td>${g(x,["timestamp","time"],"")}</td>
        <td>${g(x,["source","src_ip","source_ip"],"-")}</td>
        <td>${g(x,["destination","dst_ip"],"Ubuntu Host")}</td>
        <td>${g(x,["proto","protocol"],"SSH")}</td>
        <td>${g(x,["len","length"],84)}</td>
        <td>${g(x,["info","packet_info","description"],"")}</td>
      </tr>`).join("");
  }

  function drawCorr(rows){
    if(!rows || !rows.length)return;
    const p=panel("CORRELATED SECURITY EVENTS");
    if(!p)return;
    const tb=p.querySelector("tbody");
    if(!tb)return;
    count(p, rows.length+" EVENTS");
    tb.innerHTML=rows.slice(-10).map(x=>`
      <tr>
        <td>${String(g(x,["time","timestamp"],"")).split("T").pop()}</td>
        <td>${g(x,["source_ip","source","src_ip"],"-")}</td>
        <td>${g(x,["destination","dst_ip"],"Ubuntu Host")}</td>
        <td>${g(x,["event_description","description","info"],"")}</td>
        <td>${g(x,["severity"],"MED")}</td>
      </tr>`).join("");
  }

  function drawSSH(rows){
    if(!rows || !rows.length)return;
    const p=panel("SSH AUTH ACTIVITY");
    if(!p)return;
    count(p, rows.length+" EVENTS");
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No recent SSH events")) x.innerText="";
    });
    let box=p.querySelector("#stableSshAuth");
    if(!box){box=document.createElement("div");box.id="stableSshAuth";box.style.cssText="margin-top:8px;font-size:12px;line-height:1.55";p.appendChild(box);}
    box.innerHTML=rows.slice(-8).map(x=>
      `<div>${g(x,["time","timestamp"],"")} · ${g(x,["source","src_ip","source_ip"],"-")} · ${g(x,["info","description"],"")}</div>`
    ).join("");
  }

  function drawSuccess(rows){
    if(!rows || !rows.length)return;
    const p=panel("SUCCESSFUL LOGINS");
    if(!p)return;
    count(p, String(rows.length));
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No successful logins")) x.innerText="";
    });
    let box=p.querySelector("#stableSuccessLogin");
    if(!box){box=document.createElement("div");box.id="stableSuccessLogin";box.style.cssText="margin-top:8px;font-size:12px;line-height:1.55";p.appendChild(box);}
    box.innerHTML=rows.slice(-5).map(x=>
      `<div>${g(x,["time","timestamp"],"")} · ${g(x,["source_ip","source","src_ip"],"-")} · ${g(x,["user"],"unknown")} · SUCCESS</div>`
    ).join("");
  }

  async function loop(){
    try{
      const r=await fetch("/outputs/panel_live_state.json?t="+Date.now(),{cache:"no-store"});
      const s=await r.json();
      const h=JSON.stringify(s);
      if(h!==lastHash){
        stable=s; lastHash=h;
        drawPackets(s.packets||[]);
        drawCorr(s.correlation||[]);
        drawSSH(s.ssh_auth||[]);
        drawSuccess(s.successful_logins||[]);
      }
    }catch(e){
      if(stable.packets) {
        drawPackets(stable.packets||[]);
        drawCorr(stable.correlation||[]);
        drawSSH(stable.ssh_auth||[]);
        drawSuccess(stable.successful_logins||[]);
      }
    }
  }

  loop();
  setInterval(loop,1500);
})();
JS

python3 - <<'PY'
from pathlib import Path
p=Path("index.html")
s=p.read_text()

# disable only conflicting packet DOM scripts
for src in [
 'packet_capture_fix.js',
 'force_packet_capture_override.js',
 'force_packet_capture_dom_v2.js',
 'soc_packet_enterprise_fix.js'
]:
    s=s.replace(f'<script src="{src}"></script>', f'<!-- disabled stable distributor: {src} -->')

if '<script src="soc_nexus_stable_dom.js"></script>' not in s:
    s=s.replace('</body>', '<script src="soc_nexus_stable_dom.js"></script>\n</body>')

p.write_text(s)
PY

nohup python3 soc_panel_live_distributor.py > runtime/stable_distributor.log 2>&1 &

echo "✅ Stable live distributor installed"
echo "Now press Ctrl+F5"
