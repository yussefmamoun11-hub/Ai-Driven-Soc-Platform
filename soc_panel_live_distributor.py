#!/usr/bin/env python3
import re,json,time,datetime
from pathlib import Path
from collections import defaultdict,deque

ROOT=Path("/home/youssef-amr/soc_project")
AUTH=Path("/var/log/auth.log")
OUT=ROOT/"outputs"; DATA=ROOT/"data"; RUNTIME=ROOT/"runtime"
OUT.mkdir(exist_ok=True); DATA.mkdir(exist_ok=True); RUNTIME.mkdir(exist_ok=True)

# Queues per panel
packets_first=deque(maxlen=50)
packets_full_login=deque(maxlen=50)
packets_deep=deque(maxlen=80)
correlation_panel=deque(maxlen=40)
ssh_auth_panel=deque(maxlen=40)
successful_panel=deque(maxlen=20)
alerts_panel=deque(maxlen=20)
seen=set()
first_attempt_seen=set()
failed=defaultdict(int)

def ts(line):
    m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",line)
    return m.group(1) if m else datetime.datetime.now().isoformat(timespec="seconds")

def ip(line):
    m=re.search(r" from (\d+\.\d+\.\d+\.\d+) ",line)
    return m.group(1) if m else "-"

def user(line):
    m=re.search(r"for invalid user ([\w.-]+)",line)
    if m: return m.group(1)
    m=re.search(r"for ([\w.-]+) from ",line)
    return m.group(1) if m else "unknown"

def packet(t,src,u,info,raw,n):
    return {"no":n,"id":n,"seq":n,"timestamp":t,"time":t,"source":src,"src_ip":src,"source_ip":src,
            "destination":"Ubuntu Host","dst_ip":"Ubuntu Host","destination_ip":"Ubuntu Host",
            "proto":"SSH","protocol":"SSH","len":84,"length":84,
            "user":u,"info":info,"packet_info":info,"raw":raw.strip()}

def flush():
    OUT.mkdir(exist_ok=True)
    DATA.mkdir(exist_ok=True)
    # Write JSON per panel
    json.dump(list(packets_first),open(OUT/"packets_search_first_activity.json","w"),indent=2)
    json.dump(list(packets_full_login),open(OUT/"packets_full_login.json","w"),indent=2)
    json.dump(list(packets_deep),open(OUT/"packets_deep_extraction.json","w"),indent=2)
    json.dump(list(correlation_panel),open(OUT/"panel_correlation.json","w"),indent=2)
    json.dump(list(ssh_auth_panel),open(OUT/"ssh_auth_activity.json","w"),indent=2)
    json.dump(list(successful_panel),open(OUT/"successful_logins.json","w"),indent=2)
    json.dump(list(alerts_panel),open(OUT/"alerts.json","w"),indent=2)
    # Full live state
    full_state={
        "updated":datetime.datetime.now().isoformat(timespec="seconds"),
        "packets":list(packets_deep),
        "ssh_auth":list(ssh_auth_panel),
        "successful_logins":list(successful_panel),
        "correlation":list(correlation_panel),
        "alerts":list(alerts_panel)
    }
    json.dump(full_state,open(OUT/"panel_live_state.json","w"),indent=2)

def process(line):
    if "sshd[" not in line: return
    if "Failed password" not in line and "Accepted password" not in line: return

    t=ts(line); src=ip(line); u=user(line); n=len(packets_deep)+1
    if "Failed password" in line:
        failed[src]+=1
        info=f"Failed SSH authentication attempt for {u}"
        pkt=packet(t,src,u,info,line,n)
        packets_deep.append(pkt)
        ssh_auth_panel.append(pkt)
        alerts_panel.append({"time":t,"id":"INC-002","attack":"SSH Brute Force",
                             "source_ip":src,"user":u,"severity":"HIGH","attempts":failed[src]})
        correlation_panel.append({"time":t,"source_ip":src,"destination":"Ubuntu Host",
                                  "event_description":f"Failed SSH logins escalating — {failed[src]} attempts",
                                  "severity":"HIGH" if failed[src]>=5 else "MED","mitre":"T1110"})
        if src not in first_attempt_seen:
            first_attempt_seen.add(src)
            packets_first.append(pkt)
    if "Accepted password" in line:
        info=f"Successful SSH login for {u}"
        pkt=packet(t,src,u,info,line,n)
        packets_deep.append(pkt)
        ssh_auth_panel.append(pkt)
        successful_panel.append({"time":t,"timestamp":t,"source":src,"user":u,"status":"SUCCESS",
                                 "description":info,"raw":line.strip()})
        correlation_panel.append({"time":t,"source_ip":src,"destination":"Ubuntu Host",
                                  "event_description":"Successful SSH login after brute-force activity",
                                  "severity":"CRITICAL","mitre":"T1078"})
        packets_full_login.append(pkt)

def main():
    pos=AUTH.stat().st_size if AUTH.exists() else 0
    print("[LIVE DISTRIBUTOR] running...",flush=True)
    while True:
        try:
            if AUTH.exists():
                if AUTH.stat().st_size < pos: pos=0
                with AUTH.open("r",errors="ignore") as f:
                    f.seek(pos)
                    lines=f.readlines()
                    pos=f.tell()
                for line in lines:
                    k=line.strip()
                    if k and k not in seen:
                        seen.add(k)
                        process(line)
                flush()
        except Exception as e:
            print("[LIVE DISTRIBUTOR ERROR]",e,flush=True)
        time.sleep(0.25)

if __name__=="__main__":
    main()
