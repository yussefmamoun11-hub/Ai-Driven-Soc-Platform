#!/usr/bin/env bash
set -e
cd /home/youssef-amr/soc_project

mkdir -p backups/final_no_flicker_$(date +%Y%m%d_%H%M%S)
BKP=$(ls -td backups/final_no_flicker_* | head -1)

cp -a index.html "$BKP/index.html.bak"
cp -a soc_nexus_live_state_writer.py "$BKP/soc_nexus_live_state_writer.py.bak" 2>/dev/null || true

echo "[1] Disable conflicting JS only..."
python3 - <<'PY'
from pathlib import Path
p=Path("index.html")
s=p.read_text()

conflicts=[
  '<script src="packet_capture_fix.js"></script>',
  '<script src="force_packet_capture_override.js"></script>',
  '<script src="force_packet_capture_dom_v2.js"></script>',
  '<script src="soc_packet_enterprise_fix.js"></script>'
]
for c in conflicts:
    s=s.replace(c, f'<!-- disabled-final-no-flicker {c} -->')

if '<script src="soc_nexus_final_panels.js"></script>' not in s:
    s=s.replace('</body>', '<script src="soc_nexus_final_panels.js"></script>\n</body>')

p.write_text(s)
PY

echo "[2] Create clean final writer..."
cat > soc_nexus_live_state_writer.py <<'PY'
#!/usr/bin/env python3
import re,json,time,datetime
from pathlib import Path
from collections import deque,defaultdict

ROOT=Path("/home/youssef-amr/soc_project")
AUTH=Path("/var/log/auth.log")
OUT=ROOT/"outputs"
DATA=ROOT/"data"
OUT.mkdir(exist_ok=True)
DATA.mkdir(exist_ok=True)

packets=deque(maxlen=80)
corr=deque(maxlen=40)
ssh=deque(maxlen=60)
success=deque(maxlen=20)
alerts=deque(maxlen=40)
failed=defaultdict(int)
seen=set()

def now(): return datetime.datetime.now().isoformat(timespec="seconds")
def line_time(line):
    m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    return m.group(1) if m else now()
def ip(line):
    m=re.search(r" from (\d+\.\d+\.\d+\.\d+) ", line)
    return m.group(1) if m else "-"
def user(line):
    m=re.search(r"for invalid user ([A-Za-z0-9_.-]+)", line)
    if m:return m.group(1)
    m=re.search(r"for ([A-Za-z0-9_.-]+) from ", line)
    return m.group(1) if m else "unknown"
def write(path,obj):
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False))

def packet(t,src,u,info,raw,n):
    return {
      "no":n,"seq":n,"id":n,
      "timestamp":t,"time":t,
      "source":src,"src_ip":src,"source_ip":src,"attacker_ip":src,
      "destination":"Ubuntu Host","dst_ip":"Ubuntu Host","destination_ip":"Ubuntu Host",
      "proto":"SSH","protocol":"SSH",
      "len":84,"length":84,
      "info":info,"packet_info":info,
      "user":u,
      "raw":raw.strip()
    }

def process(line):
    if "sshd[" not in line:
        return
    if "Failed password" not in line and "Accepted password" not in line:
        return

    t=line_time(line); src=ip(line); u=user(line)
    n=len(packets)+1

    if "Failed password" in line:
        failed[src]+=1
        info=f"Failed SSH authentication attempt for {u}"
        p=packet(t,src,u,info,line,n)
        packets.append(p)
        ssh.append(p)
        corr.append({
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

    elif "Accepted password" in line:
        info=f"Successful SSH login for {u}"
        p=packet(t,src,u,info,line,n)
        packets.append(p)
        ssh.append(p)
        success.append({
          "time":t,"timestamp":t,
          "source_ip":src,"source":src,"src_ip":src,
          "user":u,"status":"SUCCESS",
          "description":f"Successful SSH login for {u} from {src}",
          "info":info,
          "raw":line.strip()
        })
        corr.append({
          "time":t,
          "source_ip":src,
          "destination":"Ubuntu Host",
          "event_description":"Successful SSH login after brute-force activity",
          "severity":"CRITICAL",
          "mitre":"T1078"
        })

def flush():
    state={
      "updated":now(),
      "packets":list(packets),
      "correlation":list(corr),
      "ssh_auth":list(ssh),
      "successful_logins":list(success),
      "alerts":list(alerts)
    }
    write(OUT/"panel_live_state.json",state)
    write(DATA/"network_packets.json",list(packets))
    write(OUT/"network_packets.json",list(packets))
    write(OUT/"correlation.json",list(corr))
    write(OUT/"ssh_auth_activity.json",list(ssh))
    write(OUT/"successful_logins.json",list(success))
    write(OUT/"alerts.json",list(alerts))

def main():
    if AUTH.exists():
        for line in AUTH.read_text(errors="ignore").splitlines()[-5000:]:
            k=line.strip()
            if k and k not in seen:
                seen.add(k); process(line)
    flush()

    pos=AUTH.stat().st_size if AUTH.exists() else 0
    print("[FINAL WRITER] running: sshd only, stable panels", flush=True)

    while True:
        try:
            if AUTH.exists():
                if AUTH.stat().st_size < pos: pos=0
                with AUTH.open("r",errors="ignore") as f:
                    f.seek(pos)
                    lines=f.readlines()
                    pos=f.tell()
                changed=False
                for line in lines:
                    k=line.strip()
                    if k and k not in seen:
                        seen.add(k)
                        before=len(packets)
                        process(line)
                        if len(packets)!=before: changed=True
                if changed:
                    flush()
        except Exception as e:
            print("[FINAL WRITER ERR]",e,flush=True)
        time.sleep(.25)

if __name__=="__main__":
    main()
PY

echo "[3] Create final DOM distributor..."
cat > soc_nexus_final_panels.js <<'JS'
(function(){
  console.log("[FINAL SOC NEXUS DISTRIBUTOR RUNNING]");

  let last = JSON.parse(localStorage.getItem("FINAL_SOC_NEXUS_STATE") || "{}");

  function clean(v,f="-"){
    return (v===undefined || v===null || v==="" || v==="undefined") ? f : v;
  }
  function get(o,ks,f="-"){
    for(const k of ks){ if(o && clean(o[k],"") !== "") return o[k]; }
    return f;
  }
  function findPanel(title){
    const T=title.toUpperCase();
    return [...document.querySelectorAll("section,article,div")]
      .filter(e=>(e.innerText||"").toUpperCase().includes(T))
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }
  function setTextNumber(panel, text){
    if(!panel)return;
    const nodes=[...panel.querySelectorAll("*")];
    const n=nodes.find(x=>!x.children.length && /^(0|\d+|\d+\s+EVENTS)$/i.test((x.innerText||"").trim()));
    if(n)n.innerText=text;
  }
  async function state(){
    try{
      const r=await fetch("/outputs/panel_live_state.json?t="+Date.now(),{cache:"no-store"});
      const s=await r.json();
      if(s && Array.isArray(s.packets)){
        last=s;
        localStorage.setItem("FINAL_SOC_NEXUS_STATE",JSON.stringify(s));
      }
    }catch(e){}
    return last || {};
  }

  function packets(rows){
    if(!rows || !rows.length)return;
    const p=findPanel("PACKET CAPTURE");
    if(!p)return;
    const tb=p.querySelector("tbody");
    if(!tb)return;

    const ip=get(rows[rows.length-1],["source","src_ip","source_ip","attacker_ip"],"-");
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("FILTER:")){
        x.innerText="FILTER: ip.src == "+ip;
      }
    });

    tb.innerHTML=rows.slice(-15).map((x,i)=>`
      <tr>
        <td>${clean(get(x,["no","seq","id"],i+1),i+1)}</td>
        <td>${clean(get(x,["timestamp","time"],""),"")}</td>
        <td>${clean(get(x,["source","src_ip","source_ip","attacker_ip"],"-"),"-")}</td>
        <td>${clean(get(x,["destination","dst_ip","destination_ip"],"Ubuntu Host"),"Ubuntu Host")}</td>
        <td>${clean(get(x,["proto","protocol"],"SSH"),"SSH")}</td>
        <td>${clean(get(x,["len","length"],84),84)}</td>
        <td>${clean(get(x,["info","packet_info","description"],""),"")}</td>
      </tr>`).join("");
  }

  function corr(rows){
    if(!rows || !rows.length)return;
    const p=findPanel("CORRELATED SECURITY EVENTS");
    if(!p)return;
    const tb=p.querySelector("tbody");
    if(!tb)return;
    setTextNumber(p, rows.length+" EVENTS");
    tb.innerHTML=rows.slice(-8).map(x=>`
      <tr>
        <td>${String(clean(get(x,["time","timestamp"],""),"")).split("T").pop()}</td>
        <td>${clean(get(x,["source_ip","source","src_ip"],"-"),"-")}</td>
        <td>${clean(get(x,["destination","dst_ip"],"Ubuntu Host"),"Ubuntu Host")}</td>
        <td>${clean(get(x,["event_description","description","info"],""),"")}</td>
        <td>${clean(get(x,["severity"],"MED"),"MED")}</td>
      </tr>`).join("");
  }

  function ssh(rows){
    if(!rows || !rows.length)return;
    const p=findPanel("SSH AUTH ACTIVITY");
    if(!p)return;
    setTextNumber(p, rows.length+" EVENTS");
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No recent SSH events")) x.innerText="";
    });
    let box=p.querySelector("#finalSshAuthRows");
    if(!box){box=document.createElement("div");box.id="finalSshAuthRows";box.style.cssText="margin-top:8px;font-size:12px;line-height:1.5";p.appendChild(box);}
    box.innerHTML=rows.slice(-8).map(x=>`
      <div>${clean(get(x,["time","timestamp"],""),"")} · ${clean(get(x,["source","source_ip","src_ip"],"-"),"-")} · ${clean(get(x,["info","description"],""),"")}</div>
    `).join("");
  }

  function success(rows){
    if(!rows || !rows.length)return;
    const p=findPanel("SUCCESSFUL LOGINS");
    if(!p)return;
    setTextNumber(p, String(rows.length));
    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No successful logins")) x.innerText="";
    });
    let box=p.querySelector("#finalSuccessRows");
    if(!box){box=document.createElement("div");box.id="finalSuccessRows";box.style.cssText="margin-top:8px;font-size:12px;line-height:1.5";p.appendChild(box);}
    box.innerHTML=rows.slice(-5).map(x=>`
      <div>${clean(get(x,["time","timestamp"],""),"")} · ${clean(get(x,["source_ip","source","src_ip"],"-"),"-")} · ${clean(get(x,["user"],"unknown"),"unknown")} · SUCCESS</div>
    `).join("");
  }

  async function draw(){
    const s=await state();
    packets(s.packets||[]);
    corr(s.correlation||[]);
    ssh(s.ssh_auth||[]);
    success(s.successful_logins||[]);
  }

  draw();
  setInterval(draw,1500);
})();
JS

echo "[4] Restart writer..."
pkill -f soc_live_panels_stable_writer.py 2>/dev/null || true
pkill -f soc_nexus_live_state_writer.py 2>/dev/null || true
nohup python3 soc_nexus_live_state_writer.py > runtime/nexus_live_state.log 2>&1 &

sleep 2
tail -20 runtime/nexus_live_state.log
echo "✅ DONE. اعمل Ctrl+F5"
