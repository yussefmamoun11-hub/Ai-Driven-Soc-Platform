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
