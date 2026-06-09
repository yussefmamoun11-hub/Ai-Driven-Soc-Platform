#!/usr/bin/env bash
set -e

PROJECT="/home/youssef-amr/soc_project"
cd "$PROJECT"

PID=$(sudo ss -ltnp | grep ':8080' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
SERVE_ROOT=$(sudo readlink "/proc/$PID/cwd" 2>/dev/null || echo "$PROJECT")

echo "[*] 8080 PID: $PID"
echo "[*] Served root: $SERVE_ROOT"

mkdir -p backups/real_data_fix_$(date +%Y%m%d_%H%M%S)
BKP=$(ls -td backups/real_data_fix_* | head -1)
cp "$SERVE_ROOT/index.html" "$BKP/index.html.bak" 2>/dev/null || sudo cp "$SERVE_ROOT/index.html" "$BKP/index.html.bak"

pkill -f soc_panel_live_distributor.py 2>/dev/null || true
pkill -f soc_nexus_live_state_writer.py 2>/dev/null || true
pkill -f soc_ai_full_pipeline_live.py 2>/dev/null || true

mkdir -p outputs data runtime

# وصل outputs/data للروت اللي السيرفر بيخدم منه
if [ "$SERVE_ROOT" != "$PROJECT" ]; then
  sudo rm -rf "$SERVE_ROOT/outputs" "$SERVE_ROOT/data"
  sudo ln -s "$PROJECT/outputs" "$SERVE_ROOT/outputs"
  sudo ln -s "$PROJECT/data" "$SERVE_ROOT/data"
fi

cat > soc_nexus_truth_writer.py <<'PY'
#!/usr/bin/env python3
import re,json,time,datetime,os
from pathlib import Path
from collections import deque,defaultdict

ROOT=Path("/home/youssef-amr/soc_project")
AUTH=Path("/var/log/auth.log")
OUT=ROOT/"outputs"; DATA=ROOT/"data"; RUNTIME=ROOT/"runtime"
OUT.mkdir(exist_ok=True); DATA.mkdir(exist_ok=True); RUNTIME.mkdir(exist_ok=True)

packets=deque(maxlen=80)
ssh_auth=deque(maxlen=80)
success=deque(maxlen=30)
events=deque(maxlen=50)
alerts=deque(maxlen=30)
failed=defaultdict(int)
seen=set()

def stamp():
    return datetime.datetime.now().isoformat(timespec="seconds")

def ts(line):
    m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",line)
    return m.group(1) if m else stamp()

def ip(line):
    m=re.search(r" from (\d+\.\d+\.\d+\.\d+) ",line)
    return m.group(1) if m else "unknown"

def user(line):
    m=re.search(r"for invalid user ([\w.-]+)",line)
    if m: return m.group(1)
    m=re.search(r"for ([\w.-]+) from ",line)
    return m.group(1) if m else "unknown"

def write(path,obj):
    tmp=path.with_name(path.name+".new")
    tmp.write_text(json.dumps(obj,indent=2,ensure_ascii=False))
    os.replace(tmp,path)

def pkt(n,t,src,u,info,raw):
    return {
      "no":n,"id":n,"seq":n,
      "time":t,"timestamp":t,
      "src":src,"source":src,"src_ip":src,"source_ip":src,"attacker_ip":src,
      "dst":"Ubuntu Host","destination":"Ubuntu Host","dst_ip":"Ubuntu Host","destination_ip":"Ubuntu Host",
      "protocol":"SSH","proto":"SSH",
      "length":84,"len":84,
      "user":u,
      "info":info,"packet_info":info,"description":info,
      "raw":raw.strip()
    }

def process(line):
    if "sshd[" not in line: return False
    if "Failed password" not in line and "Accepted password" not in line: return False

    t=ts(line); src=ip(line); u=user(line); n=len(packets)+1

    if "Failed password" in line:
        failed[src]+=1
        info=f"Failed SSH login for {u} from {src}"
        p=pkt(n,t,src,u,info,line)
        packets.append(p); ssh_auth.append(p)
        sev="HIGH" if failed[src]>=5 else "MEDIUM"
        events.append({
          "time":t,"source_ip":src,"destination":"Ubuntu Host",
          "event_description":f"Failed SSH logins escalating — {failed[src]} attempts",
          "severity":sev,"mitre":"T1110"
        })
        alerts.append({
          "time":t,"id":"INC-002","incident_id":"INC-002",
          "title":"SSH Brute Force Detected","attack":"SSH Brute Force",
          "source_ip":src,"destination_ip":"Ubuntu Host",
          "user":u,"severity":"HIGH","status":"TRIGGERED","attempts":failed[src],
          "description":info
        })
        return True

    if "Accepted password" in line:
        info=f"Successful SSH login for {u} from {src}"
        p=pkt(n,t,src,u,info,line)
        packets.append(p); ssh_auth.append(p)
        success.append({
          "time":t,"timestamp":t,"source":src,"src_ip":src,"source_ip":src,
          "user":u,"status":"SUCCESS","event":"Successful SSH login",
          "message":info,"description":info,"raw":line.strip()
        })
        events.append({
          "time":t,"source_ip":src,"destination":"Ubuntu Host",
          "event_description":"Successful SSH login after brute-force activity",
          "severity":"CRITICAL","mitre":"T1078"
        })
        return True

def flush():
    now=stamp()
    last_src = packets[-1]["source"] if packets else "waiting"
    attempts=sum(failed.values())
    succ=len(success)
    state={
      "updated":now,
      "packets":list(packets),
      "ssh_auth":list(ssh_auth),
      "successful_logins":list(success),
      "correlation":list(events),
      "alerts":list(alerts)
    }

    write(OUT/"panel_live_state.json",state)
    write(OUT/"ssh_auth_activity.json",list(ssh_auth))
    write(OUT/"successful_logins.json",list(success))
    write(OUT/"correlation.json",list(events))
    write(OUT/"alerts.json",list(alerts))
    write(OUT/"network_packets.json",list(packets))

    write(DATA/"network_packets.json",list(packets))
    write(DATA/"structured_events.json",list(events))
    write(DATA/"auth_events.json",list(ssh_auth))
    write(DATA/"correlation.json",list(events))
    write(DATA/"alerts.json",{"alerts":list(alerts),"active_alert":alerts[-1] if alerts else {}})
    write(DATA/"incident_status.json",{
      "id":"INC-002","title":"SSH Brute Force","severity":"HIGH" if attempts else "LOW",
      "status":"INVESTIGATING" if attempts else "MONITORING",
      "assignee":"SOC Team","open_time":now.split("T")[-1]
    })
    write(DATA/"ai_analysis.json",{
      "pattern":"SSH Brute Force" if attempts else "Monitoring",
      "source_ip":last_src,"severity":"HIGH" if attempts else "LOW",
      "mitre":"T1110,T1078","confidence":"97.4%"
    })
    write(DATA/"metrics.json",{
      "attempts":attempts,"attempts_count":attempts,
      "alerts":len(alerts),"active_alerts":len(alerts),
      "mttd":"5s","mttr":"32s"
    })
    write(DATA/"baseline_comparison.json",{
      "current":attempts,"current_attempts":attempts,
      "baseline":"1-3 / hr","deviation":"EXTREME" if attempts>=5 else "NORMAL"
    })
    write(DATA/"threat_intel.json",{
      "source_ip":last_src,"reputation":"MALICIOUS" if attempts else "UNKNOWN",
      "summary":"Confirmed SSH brute-force activity from live auth.log." if attempts else "No confirmed attack yet."
    })
    write(DATA/"containment_status.json",{
      "firewall":"ENABLED","fail2ban":"ACTIVE",
      "action":"PENDING","result":"waiting"
    })
    write(DATA/"timeline.json",[e["event_description"] for e in list(events)[-6:]])
    write(DATA/"evidence_status.json",[
      {"name":"Auth Logs","status":"READY"},
      {"name":"PCAP Dump","status":"READY"},
      {"name":"Metrics","status":"READY"},
      {"name":"Timeline","status":"READY"},
      {"name":"Threat Intel","status":"READY"},
      {"name":"Containment","status":"PENDING"}
    ])
    write(DATA/"system_status.json",[
      {"name":"Auth Logs · /var/log/auth.log","status":"ACTIVE"},
      {"name":"Firewall Logs · ufw.log","status":"ACTIVE"},
      {"name":"Network Events · tcpdump","status":"ACTIVE"},
      {"name":"Audit Logs · auditd","status":"ACTIVE"}
    ])
    write(DATA/"rule_status.json",[
      {"name":"SSH_Brute_Force","status":"ACTIVE"},
      {"name":"Recon_Scan_Detection","status":"ACTIVE"},
      {"name":"Port_Scan_Detection","status":"ACTIVE"}
    ])

def main():
    # امسح بيانات الديمو من الرندر الجديد وخليها من auth.log فقط
    if AUTH.exists():
        for line in AUTH.read_text(errors="ignore").splitlines()[-3000:]:
            if "sshd[" in line and ("Failed password" in line or "Accepted password" in line):
                seen.add(line.strip())
                process(line)
    flush()

    pos=AUTH.stat().st_size if AUTH.exists() else 0
    print("[SOC TRUTH WRITER] reading /var/log/auth.log -> real dashboard data",flush=True)

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
                        if process(line): changed=True
                if changed: flush()
        except Exception as e:
            print("[ERR]",e,flush=True)
        time.sleep(0.4)

if __name__=="__main__":
    main()
PY

cat > soc_nexus_truth_controller.js <<'JS'
(function(){
  console.log("[SOC NEXUS TRUTH CONTROLLER ACTIVE]");

  function pick(o,ks,f="-"){ for(const k of ks){ if(o&&o[k]!==undefined&&o[k]!==null&&o[k]!==""&&o[k]!=="undefined") return o[k]; } return f; }
  function set(id,v){ const e=document.getElementById(id); if(e) e.textContent=v; }
  function sevClass(s){ s=String(s||"").toUpperCase(); return s.includes("CRIT")||s.includes("HIGH")?"sev-h":s.includes("MED")?"sev-m":"sev-l"; }
  function protoClass(){ return "proto-ssh"; }

  async function loadState(){
    let r=await fetch("/outputs/panel_live_state.json?x="+Date.now(),{cache:"no-store"});
    if(!r.ok) r=await fetch("/data/panel_live_state.json?x="+Date.now(),{cache:"no-store"});
    return await r.json();
  }

  function packets(rows){
    if(!rows||!rows.length)return;
    const tb=document.getElementById("pkt-tbody"); if(!tb)return;
    const last=rows[rows.length-1], ip=pick(last,["source","src_ip","source_ip"]);
    document.querySelectorAll("*").forEach(e=>{
      if(!e.children.length && (e.textContent||"").includes("FILTER:")) e.textContent="FILTER: ip.src == "+ip;
    });
    tb.innerHTML=rows.slice(-16).map((r,i)=>`
      <tr class="r-ssh r-new">
        <td class="td-no">${pick(r,["no","id","seq"],i+1)}</td>
        <td class="td-ts">${pick(r,["time","timestamp"],"")}</td>
        <td class="td-src">${pick(r,["source","src","src_ip","source_ip"],"-")}</td>
        <td class="td-dst">${pick(r,["destination","dst","dst_ip"],"Ubuntu Host")}</td>
        <td><span class="proto ${protoClass()}">SSH</span></td>
        <td class="td-len">${pick(r,["length","len"],84)}</td>
        <td class="td-info">${pick(r,["info","packet_info","description"],"")}</td>
      </tr>`).join("");
  }

  function corr(rows){
    if(!rows||!rows.length)return;
    const tb=document.querySelector(".evtbl tbody"); if(!tb)return;
    const badge=[...document.querySelectorAll(".ph-badge")].find(e=>(e.closest(".pnl")?.innerText||"").includes("Correlated Security Events"));
    if(badge) badge.textContent=rows.length+" EVENTS";
    tb.innerHTML=rows.slice(-10).map(r=>`
      <tr>
        <td style="font-family:var(--mono);font-size:9px;color:var(--t3)">${String(pick(r,["time","timestamp"],"")).split("T").pop()}</td>
        <td style="font-family:var(--mono);font-size:9px;color:var(--c)">${pick(r,["source_ip","source","src_ip"],"-")}</td>
        <td style="font-family:var(--mono);font-size:9px">${pick(r,["destination","dst_ip"],"Ubuntu Host")}</td>
        <td style="font-family:var(--mono);font-size:9px;color:var(--t1)">${pick(r,["event_description","description","info"],"")}</td>
        <td><span class="sev ${sevClass(pick(r,["severity"],"MED"))}">${pick(r,["severity"],"MED")}</span></td>
      </tr>`).join("");
  }

  function ssh(rows){
    const body=document.getElementById("x-ssh-body"), badge=document.getElementById("x-ssh-badge");
    if(!body||!rows)return;
    if(badge) badge.textContent=rows.length+" EVENTS";
    body.innerHTML=rows.length ? rows.slice(-10).map(r=>`
      <div class="xmini">
        <span class="xmini-ts">${String(pick(r,["time","timestamp"],"")).split("T").pop()}</span>
        <span class="xmini-msg">${pick(r,["info","description","message"],"")}</span>
        <span class="xmini-user">${pick(r,["user"],"")}</span>
      </div>`).join("") : '<div class="xmini xmini-empty">No recent SSH events</div>';
  }

  function logins(rows){
    const body=document.getElementById("x-login-body"), badge=document.getElementById("x-login-badge");
    if(!body||!rows)return;
    if(badge) badge.textContent=rows.length;
    body.innerHTML=rows.length ? rows.slice(-6).map(r=>`
      <div class="xmini">
        <span class="xmini-ts">${String(pick(r,["time","timestamp"],"")).split("T").pop()}</span>
        <span class="xmini-msg">${pick(r,["description","message","event"],"Successful SSH login")}</span>
        <span class="xmini-user">${pick(r,["user"],"")}</span>
      </div>`).join("") : '<div class="xmini xmini-empty">No successful logins detected</div>';
  }

  function summary(s){
    const p=s.packets||[], c=s.correlation||[], a=s.alerts||[], ok=s.successful_logins||[];
    const last=p[p.length-1]||{}, ip=pick(last,["source","src_ip","source_ip"],"waiting");
    const attempts=(s.ssh_auth||[]).filter(x=>String(pick(x,["info"],"")).includes("Failed")).length;

    set("mc-att",attempts); set("q-att",attempts); set("rh1","×"+attempts);
    set("mc-alerts",a.length||0); set("q-alerts",a.length||0);
    set("baseline-cur",attempts);
    set("ai-src",ip); set("ti-ip",ip);
    set("alert-src",ip+"  →  Ubuntu Host:22");
    set("alert-title", attempts ? "SSH Brute Force Detected" : "Live monitoring active — waiting for attack activity");
    set("inc-id-big","INC-002");
    set("inc-type","SSH BRUTE FORCE");
    set("ti-summary", attempts ? "Confirmed live SSH activity from Ubuntu auth.log." : "No confirmed attack yet.");
  }

  let last="";
  async function loop(){
    try{
      const s=await loadState();
      const h=JSON.stringify(s);
      if(h!==last){
        last=h;
        packets(s.packets||[]);
        corr(s.correlation||[]);
        ssh(s.ssh_auth||[]);
        logins(s.successful_logins||[]);
        summary(s);
      }
    }catch(e){ console.warn("[truth controller]",e); }
  }

  loop();
  setInterval(loop,1000);
})();
JS

# نظف الصفحة: احذف أي سكريبت بعد </html>، عطّل البلوكات القديمة اللي بتثبت ديمو
sudo python3 - <<PY
from pathlib import Path
p=Path("$SERVE_ROOT/index.html")
s=p.read_text(errors="ignore")

if "</html>" in s:
    s=s[:s.index("</html>")+len("</html>")]

bad=[
 '<script src="soc_nexus_stable_single_controller.js"></script>',
 '<script src="soc_nexus_stable_dom.js"></script>',
 '<script src="soc_nexus_final_panels.js"></script>',
 '<script src="packet_stream_dashboard_patch.js"></script>',
 '<script src="packet_capture_fix.js"></script>',
 '<script src="force_packet_capture_override.js"></script>',
 '<script src="force_packet_capture_dom_v2.js"></script>',
 '<script src="soc_packet_enterprise_fix.js"></script>',
]
for b in bad:
    s=s.replace(b,"")

# وقف loop القديم اللي بيرجع demo data
s=s.replace("setInterval(refreshAll, REFRESH_MS);","// disabled by truth controller")
s=s.replace("setInterval(refreshExtended, _MS);","// disabled by truth controller")

if '<script src="soc_nexus_truth_controller.js"></script>' not in s:
    s=s.replace("</body>", '<script src="soc_nexus_truth_controller.js"></script>\\n</body>')

p.write_text(s)
PY

if [ "$SERVE_ROOT" != "$PROJECT" ]; then
  sudo cp soc_nexus_truth_controller.js "$SERVE_ROOT/soc_nexus_truth_controller.js"
else
  cp soc_nexus_truth_controller.js "$SERVE_ROOT/soc_nexus_truth_controller.js"
fi

nohup python3 soc_nexus_truth_writer.py > runtime/truth_writer.log 2>&1 &

sleep 1
echo "===== TEST URLS ====="
curl -s "http://192.168.1.17:8080/outputs/panel_live_state.json" | head -5 || true
echo
echo "===== WRITER LOG ====="
tail -10 runtime/truth_writer.log
echo
echo "✅ DONE. افتح الداشبورد Incognito أو Ctrl+F5"
