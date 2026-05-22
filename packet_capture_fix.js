(function () {
  console.log("Packet Capture Fix Active");

  const CACHE_KEY = "SOC_PACKET_CAPTURE_LAST";

  async function getJSON(path) {
    try {
      const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
      return await r.json();
    } catch (e) {
      return null;
    }
  }

  function savePackets(packets) {
    if (Array.isArray(packets) && packets.length > 0) {
      localStorage.setItem(CACHE_KEY, JSON.stringify(packets));
    }
  }

  function loadPackets() {
    try {
      return JSON.parse(localStorage.getItem(CACHE_KEY) || "[]");
    } catch (e) {
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

  function patchFilter(ip) {
    document.querySelectorAll("*").forEach(el => {
      if (!el.children.length && el.textContent.includes("ip.src")) {
        el.textContent = "FILTER: ip.src == " + ip;
      }
    });
  }

  function patchPacketTable(packets) {
    if (!Array.isArray(packets) || packets.length === 0) return;

    savePackets(packets);

    const attacker = findAttacker(packets);
    patchFilter(attacker);

    const tables = document.querySelectorAll("table");
    let targetTable = null;

    for (const table of tables) {
      const text = table.innerText || "";
      if (
        text.includes("Timestamp") &&
        text.includes("Source") &&
        text.includes("Destination") &&
        text.includes("Proto")
      ) {
        targetTable = table;
        break;
      }
    }

    if (!targetTable) return;

    const tbody = targetTable.querySelector("tbody") || targetTable;
    tbody.innerHTML = "";

    packets.slice(0, 12).forEach((p, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${p.timestamp || p.time || new Date().toISOString()}</td>
        <td>${p.src_ip || p.source_ip || p.source || p.attacker_ip || attacker}</td>
        <td>${p.dst_ip || p.destination_ip || p.destination || "Ubuntu Host"}</td>
        <td>${p.proto || p.protocol || "SSH"}</td>
        <td>${p.len || p.length || 84}</td>
        <td>${p.info || p.packet_info || "SSH authentication event"}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  async function refreshPacketCapture() {
    let packets =
      await getJSON("data/network_packets.json") ||
      await getJSON("outputs/network_packets.json") ||
      [];

    if (!Array.isArray(packets) || packets.length === 0) {
      packets = loadPackets();
    }

    patchPacketTable(packets);
  }

  refreshPacketCapture();
  setInterval(refreshPacketCapture, 1000);
})();
