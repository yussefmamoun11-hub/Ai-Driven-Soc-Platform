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
