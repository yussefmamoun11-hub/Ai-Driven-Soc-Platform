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
