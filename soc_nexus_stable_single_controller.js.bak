(function(){
  console.log("[SOC NEXUS SINGLE CONTROLLER ACTIVE]");

  let lastHash = "";
  let frozenState = null;

  function v(obj, keys, fallback="-"){
    for(const k of keys){
      const x = obj && obj[k];
      if(x !== undefined && x !== null && x !== "" && x !== "undefined") return x;
    }
    return fallback;
  }

  function findPanel(title){
    const t = title.toUpperCase();
    return [...document.querySelectorAll("section,article,div")]
      .filter(e => (e.innerText || "").toUpperCase().includes(t))
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function setCount(panel, text){
    if(!panel) return;
    const nodes=[...panel.querySelectorAll("*")];
    const node=nodes.find(x=>!x.children.length && /^(0|\d+|\d+\s+EVENTS)$/i.test((x.innerText||"").trim()));
    if(node) node.innerText = text;
  }

  function renderPacket(rows){
    if(!rows || !rows.length) return;
    const p=findPanel("PACKET CAPTURE");
    if(!p) return;
    const tb=p.querySelector("tbody");
    if(!tb) return;

    const last=rows[rows.length-1];
    const ip=v(last,["source","src_ip","source_ip","attacker_ip"],"-");

    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("FILTER:")){
        x.innerText="FILTER: ip.src == "+ip;
      }
    });

    tb.innerHTML = rows.slice(-15).map((x,i)=>`
      <tr>
        <td>${v(x,["no","seq","id"],i+1)}</td>
        <td>${v(x,["timestamp","time"],"")}</td>
        <td>${v(x,["source","src_ip","source_ip","attacker_ip"],"-")}</td>
        <td>${v(x,["destination","dst_ip","destination_ip"],"Ubuntu Host")}</td>
        <td>${v(x,["proto","protocol"],"SSH")}</td>
        <td>${v(x,["len","length"],84)}</td>
        <td>${v(x,["info","packet_info","description"],"")}</td>
      </tr>
    `).join("");
  }

  function renderCorrelation(rows){
    if(!rows || !rows.length) return;
    const p=findPanel("CORRELATED SECURITY EVENTS");
    if(!p) return;
    const tb=p.querySelector("tbody");
    if(!tb) return;

    setCount(p, rows.length + " EVENTS");

    tb.innerHTML = rows.slice(-10).map(x=>`
      <tr>
        <td>${String(v(x,["time","timestamp"],"")).split("T").pop()}</td>
        <td>${v(x,["source_ip","source","src_ip"],"-")}</td>
        <td>${v(x,["destination","dst_ip"],"Ubuntu Host")}</td>
        <td>${v(x,["event_description","description","info"],"")}</td>
        <td>${v(x,["severity"],"MED")}</td>
      </tr>
    `).join("");
  }

  function renderSSH(rows){
    if(!rows || !rows.length) return;
    const p=findPanel("SSH AUTH ACTIVITY");
    if(!p) return;

    setCount(p, rows.length + " EVENTS");

    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No recent SSH events")) x.innerText="";
    });

    let box=p.querySelector("#singleSshAuthRows");
    if(!box){
      box=document.createElement("div");
      box.id="singleSshAuthRows";
      box.style.cssText="margin-top:8px;font-size:12px;line-height:1.55";
      p.appendChild(box);
    }

    box.innerHTML = rows.slice(-8).map(x=>`
      <div>${v(x,["time","timestamp"],"")} · ${v(x,["source","src_ip","source_ip"],"-")} · ${v(x,["info","description"],"")}</div>
    `).join("");
  }

  function renderSuccess(rows){
    if(!rows || !rows.length) return;
    const p=findPanel("SUCCESSFUL LOGINS");
    if(!p) return;

    setCount(p, String(rows.length));

    [...p.querySelectorAll("*")].forEach(x=>{
      if(!x.children.length && (x.innerText||"").includes("No successful logins")) x.innerText="";
    });

    let box=p.querySelector("#singleSuccessRows");
    if(!box){
      box=document.createElement("div");
      box.id="singleSuccessRows";
      box.style.cssText="margin-top:8px;font-size:12px;line-height:1.55";
      p.appendChild(box);
    }

    box.innerHTML = rows.slice(-5).map(x=>`
      <div>${v(x,["time","timestamp"],"")} · ${v(x,["source_ip","source","src_ip"],"-")} · ${v(x,["user"],"unknown")} · SUCCESS</div>
    `).join("");
  }

  function draw(s){
    renderPacket(s.packets || []);
    renderCorrelation(s.correlation || []);
    renderSSH(s.ssh_auth || []);
    renderSuccess(s.successful_logins || []);
  }

  async function loop(){
    try{
      const r=await fetch("/outputs/panel_live_state.json?t="+Date.now(), {cache:"no-store"});
      const s=await r.json();
      const h=JSON.stringify(s);

      if(h !== lastHash){
        lastHash = h;
        frozenState = s;
        draw(s);
      } else if(frozenState) {
        draw(frozenState);
      }
    }catch(e){
      if(frozenState) draw(frozenState);
    }
  }

  loop();
  setInterval(loop, 1500);
})();
