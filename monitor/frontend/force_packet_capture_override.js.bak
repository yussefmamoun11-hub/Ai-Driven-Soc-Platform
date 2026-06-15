(function () {
  console.log("FORCE Packet Capture Override Active");

  async function getPackets() {
    const paths = [
      "data/network_packets.json",
      "outputs/network_packets.json",
      "final_attack_snapshot/network_packets.json"
    ];

    for (const path of paths) {
      try {
        const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
        const data = await r.json();
        if (Array.isArray(data) && data.length > 0) {
          localStorage.setItem("SOC_FORCE_PACKETS", JSON.stringify(data));
          return data;
        }
      } catch (e) {}
    }

    try {
      return JSON.parse(localStorage.getItem("SOC_FORCE_PACKETS") || "[]");
    } catch {
      return [];
    }
  }

  function findAttacker(packets) {
    for (const p of packets) {
      const ip = p.src_ip || p.source_ip || p.source || p.attacker_ip;
      if (ip && ip !== "Ubuntu Host") return ip;
    }
    return "192.168.1.78";
  }

  function updateFilter(ip) {
    document.querySelectorAll("*").forEach(el => {
      if (!el.children.length && el.textContent.includes("FILTER:")) {
        el.textContent = "FILTER: ip.src == " + ip;
      }
    });
  }

  function renderRows(packets) {
    const tables = document.querySelectorAll("table");
    let table = null;

    for (const t of tables) {
      const txt = t.innerText || "";
      if (
        txt.includes("TIMESTAMP") &&
        txt.includes("SOURCE") &&
        txt.includes("DESTINATION") &&
        txt.includes("PROTO")
      ) {
        table = t;
        break;
      }
    }

    if (!table) return;

    const tbody = table.querySelector("tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    packets.slice(0, 12).forEach((p, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${p.timestamp || p.time || new Date().toISOString()}</td>
        <td>${p.src_ip || p.source_ip || p.source || p.attacker_ip || "192.168.1.78"}</td>
        <td>${p.dst_ip || p.destination || "Ubuntu Host"}</td>
        <td>${p.proto || p.protocol || "SSH"}</td>
        <td>${p.len || p.length || 84}</td>
        <td>${p.info || p.packet_info || "SSH authentication event"}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  async function refresh() {
    const packets = await getPackets();
    if (!packets.length) return;

    const attacker = findAttacker(packets);
    updateFilter(attacker);
    renderRows(packets);
  }

  refresh();
  setInterval(refresh, 1000);
})();
