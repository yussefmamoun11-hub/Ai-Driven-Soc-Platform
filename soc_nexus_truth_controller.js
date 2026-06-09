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
