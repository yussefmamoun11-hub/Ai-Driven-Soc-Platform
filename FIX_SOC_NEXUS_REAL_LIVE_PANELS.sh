#!/usr/bin/env bash
set -e
cd /home/youssef-amr/soc_project

mkdir -p outputs data runtime backups/live_panel_fix_$(date +%Y%m%d_%H%M%S)
BKP=$(ls -td backups/live_panel_fix_* | head -1)

cp -a force_packet_capture_dom_v2.js "$BKP/force_packet_capture_dom_v2.js.bak" 2>/dev/null || true

cat > soc_nexus_live_state_writer.py <<'PY'
#!/usr/bin/env python3
import re,json,time,datetime
from pathlib import Path
from collections import deque,defaultdict

ROOT=Path("/home/youssef-amr/soc_project")
AUTH=Path("/var/log/auth.log")
OUT=ROOT/"outputs"
DATA=ROOT/"data"

STATE=OUT/"panel_live_state.json"
PACKETS=DATA/"network_packets.json"
CORR=OUT/"correlation.json"
SSH=OUT/"ssh_auth_activity.json"
SUCCESS=OUT/"successful_logins.json"
ALERTS=OUT/"alerts.json"

packets=deque(maxlen=40)
corr=deque(maxlen=20)
ssh=deque(maxlen=30)
success=deque(maxlen=15)
alerts=deque(maxlen=20)
failed=defaultdict(list)
seen=set()

def now(): return datetime.datetime.now().isoformat(timespec="seconds")

def ip(line):
    m=re.search(r"from (\d+\.\d+\.\d+\.\d+)",line)
    return m.group(1) if m else "-"

def user(line):
    m=re.search(r"for invalid user ([A-Za-z0-9_.-]+)",line)
    if m:return m.group(1)
    m=re.search(r"for ([A-Za-z0-9_.-]+)",line)
    return m.group(1) if m else "unknown"

def write(path,obj):
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(obj,indent=2,ensure_ascii=False))
    tmp.replace(path)

def process(line):
    t=now(); src=ip(line); u=user(line)

    if "Failed password" in line:
        failed[src].append(time.time())
        attempts=len([x for x in failed[src] if time.time()-x<180])

        p={
          "timestamp":t,"source":src,"src_ip":src,
          "destination":"192.168.8.111","proto":"SSH","len":84,
          "info":f"Failed SSH authentication attempt for {u}",
          "raw":line.strip()
        }
        packets.append(p); ssh.append(p)

        corr.append({
          "time":t,"source_ip":src,"destination":"192.168.8.111",
          "event_description":f"Failed SSH logins escalating — {attempts} attempts",
          "severity":"HIGH" if attempts>=5 else "MED"
        })

        alerts.append({
          "time":t,"id":"INC-002","attack":"SSH Brute Force",
          "source_ip":src,"severity":"HIGH","attempts":attempts
        })

    elif "Accepted password" in line:
        e={
          "time":t,"source_ip":src,"user":u,"status":"SUCCESS",
          "description":f"Successful SSH login for {u} from {src}",
          "raw":line.strip()
        }
        success.append(e); ssh.append(e)
        packets.append({
          "timestamp":t,"source":src,"src_ip":src,
          "destination":"192.168.8.111","proto":"SSH","len":84,
          "info":f"Successful SSH login for {u}","raw":line.strip()
        })
        corr.append({
          "time":t,"source_ip":src,"destination":"192.168.8.111",
          "event_description":"Successful SSH login after brute-force activity",
          "severity":"CRITICAL"
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
    write(STATE,state)
    write(PACKETS,list(packets))
    write(CORR,list(corr))
    write(SSH,list(ssh))
    write(SUCCESS,list(success))
    write(ALERTS,list(alerts))

def main():
    pos=0
    if AUTH.exists():
        pos=max(0,AUTH.stat().st_size-500000)
    print("[SOC NEXUS LIVE STATE] running",flush=True)
    while True:
        try:
            if AUTH.exists():
                if AUTH.stat().st_size < pos: pos=0
                with AUTH.open("r",errors="ignore") as f:
                    f.seek(pos); lines=f.readlines(); pos=f.tell()
                for line in lines:
                    k=line.strip()
                    if k and k not in seen:
                        seen.add(k)
                        process(line)
                flush()
        except Exception as e:
            print("[ERR]",e,flush=True)
        time.sleep(.25)

if __name__=="__main__":
    main()
PY

cat > force_packet_capture_dom_v2.js <<'JS'
(function(){
  console.log("[SOC NEXUS LIVE PANEL FIX ACTIVE]");

  let lastState = JSON.parse(localStorage.getItem("SOC_NEXUS_LAST_STATE") || "{}");

  async function loadState(){
    try{
      const r = await fetch("/outputs/panel_live_state.json?t="+Date.now(), {cache:"no-store"});
      const s = await r.json();
      if(s && (s.packets||s.correlation||s.ssh_auth||s.successful_logins)){
        lastState=s;
        localStorage.setItem("SOC_NEXUS_LAST_STATE", JSON.stringify(s));
      }
    }catch(e){}
    return lastState || {};
  }

  function panelByTitle(txt){
    txt=txt.toUpperCase();
    return [...document.querySelectorAll("section,div,article")]
      .filter(x=>(x.innerText||"").toUpperCase().includes(txt))
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function setBadge(panel, text){
    if(!panel)return;
    const badges=[...panel.querySelectorAll("*")].filter(x=>(x.innerText||"").match(/^\d+\s*(EVENTS)?$|^0$/));
    if(badges[0]) badges[0].innerText=text;
  }

  function patchPacket(rows){
    if(!rows || !rows.length) return;
    const p=panelByTitle("PACKET CAPTURE");
    if(!p)return;
    const tbody=p.querySelector("tbody");
    if(!tbody)return;
    const ip=rows[rows.length-1].source || rows[rows.length-1].src_ip || "-";
    [...p.querySelectorAll("*")].forEach(e=>{
      if(!e.children.length && (e.innerText||"").includes("FILTER:")) e.innerText="FILTER: ip.src == "+ip;
    });
    tbody.innerHTML=rows.slice(-18).map((x,i)=>`
      <tr>
        <td>${i+1}</td>
        <td>${x.timestamp||x.time||""}</td>
        <td>${x.source||x.src_ip||"-"}</td>
        <td>${x.destination||"192.168.8.111"}</td>
        <td><span>SSH</span></td>
        <td>${x.len||84}</td>
        <td>${x.info||x.packet_info||""}</td>
      </tr>`).join("");
  }

  function patchCorrelation(rows){
    if(!rows || !rows.length) return;
    const p=panelByTitle("CORRELATED SECURITY EVENTS");
    if(!p)return;
    setBadge(p, rows.length+" EVENTS");
    const tbody=p.querySelector("tbody");
    if(!tbody)return;
    tbody.innerHTML=rows.slice(-10).map(x=>`
      <tr>
        <td>${(x.time||"").split("T").pop()}</td>
        <td>${x.source_ip||"-"}</td>
        <td>${x.destination||"192.168.8.111"}</td>
        <td>${x.event_description||x.description||""}</td>
        <td>${x.severity||"MED"}</td>
      </tr>`).join("");
  }

  function patchSSH(rows){
    if(!rows || !rows.length) return;
    const p=panelByTitle("SSH AUTH ACTIVITY");
    if(!p)return;
    setBadge(p, rows.length+" EVENTS");
    const old=[...p.querySelectorAll("*")].find(x=>!x.children.length && (x.innerText||"").includes("No recent SSH events"));
    if(old) old.innerText="";
    let box=p.querySelector("#sshLiveRows");
    if(!box){box=document.createElement("div");box.id="sshLiveRows";p.appendChild(box);}
    box.innerHTML=rows.slice(-8).map(x=>`
      <div>${x.timestamp||x.time||""} · ${x.source||x.source_ip||"-"} · ${x.info||x.description||""}</div>
    `).join("");
  }

  function patchSuccess(rows){
    if(!rows || !rows.length) return;
    const p=panelByTitle("SUCCESSFUL LOGINS");
    if(!p)return;
    setBadge(p, String(rows.length));
    const old=[...p.querySelectorAll("*")].find(x=>!x.children.length && (x.innerText||"").includes("No successful logins"));
    if(old) old.innerText="";
    let box=p.querySelector("#successLiveRows");
    if(!box){box=document.createElement("div");box.id="successLiveRows";p.appendChild(box);}
    box.innerHTML=rows.slice(-5).map(x=>`
      <div>${x.time||""} · ${x.source_ip||"-"} · ${x.user||"unknown"} · SUCCESS</div>
    `).join("");
  }

  async function tick(){
    const s=await loadState();
    patchPacket(s.packets||[]);
    patchCorrelation(s.correlation||[]);
    patchSSH(s.ssh_auth||[]);
    patchSuccess(s.successful_logins||[]);
  }

  tick();
  setInterval(tick,500);
})();
JS

chmod +x soc_nexus_live_state_writer.py
sudo chown -R $USER:$USER outputs data runtime

pkill -f soc_nexus_live_state_writer.py 2>/dev/null || true
nohup python3 soc_nexus_live_state_writer.py > runtime/nexus_live_state.log 2>&1 &

echo "✅ FIX ACTIVE. Refresh browser with Ctrl+F5"
tail -20 runtime/nexus_live_state.log
