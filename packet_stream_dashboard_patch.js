(function(){
  console.log("ENTERPRISE PACKET STREAM ACTIVE");

  const API = "http://192.168.1.17:9101";

  function findPacketPanel(){
    const nodes = [...document.querySelectorAll("div,section,main,article")];
    return nodes
      .filter(n => {
        const t = (n.innerText || "").toUpperCase();
        return t.includes("PACKET CAPTURE") && t.includes("TIMESTAMP") && t.includes("SOURCE");
      })
      .sort((a,b)=>(a.innerText||"").length-(b.innerText||"").length)[0];
  }

  function render(packets){
    if(!packets || !packets.length) return;

    const panel = findPacketPanel();
    if(!panel) return;

    const ip = packets[packets.length - 1].src_ip || packets[packets.length - 1].source;

    panel.querySelectorAll("*").forEach(el=>{
      if(!el.children.length && el.textContent.includes("FILTER:")){
        el.textContent = "FILTER: ip.src == " + ip;
      }
    });

    let live = document.getElementById("enterprise-live-packet-stream");
    if(!live){
      live = document.createElement("div");
      live.id = "enterprise-live-packet-stream";
      live.style.cssText = `
        margin-top:8px;
        padding:8px;
        border:1px solid rgba(0,234,255,.45);
        background:#050d18;
        position:relative;
        z-index:99999;
      `;
      panel.prepend(live);
    }

    live.innerHTML = `
      <div style="color:#00eaff;font-weight:bold;letter-spacing:3px;margin-bottom:6px;">
        LIVE PACKET STREAM · ${ip}
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:12px;color:#9fb3d9;">
        <thead>
          <tr style="color:#6f7fa4;letter-spacing:2px;">
            <th>No.</th><th>Timestamp</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Packet Info</th>
          </tr>
        </thead>
        <tbody>
          ${packets.slice(-12).map((p,i)=>`
            <tr>
              <td>${i+1}</td>
              <td>${p.timestamp || ""}</td>
              <td style="color:#00eaff">${p.src_ip || p.source || ""}</td>
              <td>${p.destination || "Ubuntu Host"}</td>
              <td style="color:#ffbf00">${p.proto || "SSH"}</td>
              <td>${p.len || 84}</td>
              <td>${p.info || "SSH event"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function start(){
    try{
      const es = new EventSource(API + "/stream");
      es.onmessage = e => {
        const data = JSON.parse(e.data);
        if(data.packets && data.packets.length){
          localStorage.setItem("SOC_PACKET_STREAM_LAST", JSON.stringify(data.packets));
          render(data.packets);
        }
      };
      es.onerror = () => fallback();
    }catch(e){
      fallback();
    }
  }

  async function fallback(){
    try{
      const r = await fetch(API + "/api/packets?t=" + Date.now(), {cache:"no-store"});
      const d = await r.json();
      if(d.packets && d.packets.length){
        localStorage.setItem("SOC_PACKET_STREAM_LAST", JSON.stringify(d.packets));
        render(d.packets);
      }else{
        const old = JSON.parse(localStorage.getItem("SOC_PACKET_STREAM_LAST") || "[]");
        render(old);
      }
    }catch(e){
      const old = JSON.parse(localStorage.getItem("SOC_PACKET_STREAM_LAST") || "[]");
      render(old);
    }
  }

  start();
  setInterval(fallback, 2000);
})();
