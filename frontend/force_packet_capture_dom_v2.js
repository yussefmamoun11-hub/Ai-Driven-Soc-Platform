(function () {
  console.log("FORCE Packet Capture DOM V2 Active");

  async function loadPackets() {
    for (const p of ["data/network_packets.json","outputs/network_packets.json","final_attack_snapshot/network_packets.json"]) {
      try {
        const r = await fetch(p + "?t=" + Date.now(), {cache:"no-store"});
        const d = await r.json();
        if (Array.isArray(d) && d.length) {
          localStorage.setItem("SOC_PACKET_LAST", JSON.stringify(d));
          return d;
        }
      } catch(e) {}
    }
    return JSON.parse(localStorage.getItem("SOC_PACKET_LAST") || "[]");
  }

  function findPacketSection() {
    const all = [...document.querySelectorAll("section, div, article, main")];
    return all.find(el => (el.innerText || "").includes("Packet Capture") && (el.innerText || "").includes("Timestamp"));
  }

  async function draw() {
    const packets = await loadPackets();
    if (!packets.length) return;

    const ip = packets[0].src_ip || packets[0].source_ip || "192.168.1.78";
    const section = findPacketSection();
    if (!section) return;

    section.querySelectorAll("*").forEach(el => {
      if (!el.children.length && el.textContent.includes("FILTER:")) {
        el.textContent = "FILTER: ip.src == " + ip;
      }
    });

    let table = section.querySelector("table");
    if (!table) return;

    const tbody = table.querySelector("tbody") || table;
    tbody.innerHTML = packets.slice(0,12).map((p,i)=>`
      <tr>
        <td>${i+1}</td>
        <td>${p.timestamp || p.time}</td>
        <td>${p.src_ip || p.source_ip || ip}</td>
        <td>${p.dst_ip || p.destination || "Ubuntu Host"}</td>
        <td>${p.proto || p.protocol || "SSH"}</td>
        <td>${p.len || p.length || 84}</td>
        <td>${p.info || p.packet_info || "SSH authentication event"}</td>
      </tr>
    `).join("");
  }

  draw();
  setInterval(draw, 300);
})();
