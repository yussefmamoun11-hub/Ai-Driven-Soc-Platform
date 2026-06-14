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

    if "sshd[" in line and "Failed password" in line:
        failed[src].append(time.time())
        attempts=len([x for x in failed[src] if time.time()-x<180])

        p={
          "timestamp":t,"source":src,"src_ip":src,
          "destination":"192.168.1.17","proto":"SSH","len":84,
          "info":f"Failed SSH authentication attempt for {u}",
          "raw":line.strip()
        }
        packets.append(p); ssh.append(p)

        corr.append({
          "time":t,"source_ip":src,"destination":"192.168.1.17",
          "event_description":f"Failed SSH logins escalating — {attempts} attempts",
          "severity":"HIGH" if attempts>=5 else "MED"
        })

        alerts.append({
          "time":t,"id":"INC-002","attack":"SSH Brute Force",
          "source_ip":src,"severity":"HIGH","attempts":attempts
        })

    elif "sshd[" in line and "Accepted password" in line:
        e={
          "time":t,"source_ip":src,"user":u,"status":"SUCCESS",
          "description":f"Successful SSH login for {u} from {src}",
          "raw":line.strip()
        }
        success.append(e); ssh.append(e)
        packets.append({
          "timestamp":t,"source":src,"src_ip":src,
          "destination":"192.168.1.17","proto":"SSH","len":84,
          "info":f"Successful SSH login for {u}","raw":line.strip()
        })
        corr.append({
          "time":t,"source_ip":src,"destination":"192.168.1.17",
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
