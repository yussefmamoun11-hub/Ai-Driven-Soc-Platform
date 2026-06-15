const LIVE_FILES = {
  metrics: "data/metrics.json",
  incident: "data/incident_status.json",
  threat: "data/threat_intel.json",
  ai: "data/ai_analysis.json",
  containment: "data/containment_status.json",
  evidence: "data/evidence_status.json",
  baseline: "data/baseline_comparison.json",
  alerts: "data/alerts.json",
  correlation: "outputs/correlation.json",
  privilege: "outputs/privilege_activity.json"
};

window.LAST_GOOD_SOC = window.LAST_GOOD_SOC || {};

async function liveFetch(key, path) {
  try {
    const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
    const d = await r.json();
    if (d && (Array.isArray(d) ? d.length : Object.keys(d).length)) {
      window.LAST_GOOD_SOC[key] = d;
      return d;
    }
  } catch(e) {}
  return window.LAST_GOOD_SOC[key] || {};
}

function replaceExact(oldText, newText) {
  document.querySelectorAll("*").forEach(el => {
    if (!el.children.length && el.textContent.trim() === oldText) {
      el.textContent = newText;
    }
  });
}

function updateTextNear(label, value) {
  if (value === undefined || value === null) return;
  document.querySelectorAll("*").forEach(el => {
    if (!el.children.length && el.textContent.trim().toLowerCase().includes(label.toLowerCase())) {
      let n = el.nextElementSibling;
      if (n && !n.children.length) n.textContent = String(value).toUpperCase();
    }
  });
}

function paintSOC(state) {
  const m = state.metrics || {};
  const i = state.incident || {};
  const t = state.threat || {};
  const ai = state.ai || {};
  const c = state.containment || {};
  const e = state.evidence || {};
  const b = state.baseline || {};
  const corr = state.correlation || {};

  const attempts = m.attempts ?? m.attempts_count ?? b.current_attempts ?? corr.failed_attempts ?? 0;
  const alerts = m.alerts ?? m.alert_count ?? corr.alerts ?? 0;
  const severity = (i.severity || ai.severity || corr.final_severity || "HIGH").toUpperCase();
  const status = (i.status || c.status || "INVESTIGATING").toUpperCase();

  updateTextNear("Severity", severity);
  updateTextNear("Attempts", attempts);
  updateTextNear("Alerts", alerts);
  updateTextNear("MTTD", m.mttd || "5s");
  updateTextNear("MTTR", m.mttr || "32s");
  updateTextNear("Incident", i.incident_id || i.id || corr.incident_id || "INC-003");
  updateTextNear("Status", status);
  updateTextNear("Reputation", t.reputation || "HIGH RISK");
  updateTextNear("Containment", c.status || "CONTAINED");
  updateTextNear("Evidence", e.status || "PRESERVED");
  updateTextNear("Baseline", b.deviation || "EXTREME");

  replaceExact("No confirmed attack yet.", t.summary || "Confirmed SSH brute force and multi-stage intrusion activity.");
  replaceExact("waiting", c.result || "Attack successfully blocked");
  replaceExact("PENDING", c.block_ip_rule || "APPLIED");
  replaceExact("MONITORING", status);
  replaceExact("LOW", severity);
  replaceExact("PARTIAL", c.status || "CONTAINED");

  document.title = "SOC NEXUS · LIVE";
}

async function refreshSOC() {
  const state = {};
  for (const [k,p] of Object.entries(LIVE_FILES)) {
    state[k] = await liveFetch(k,p);
  }
  paintSOC(state);
}

refreshSOC();
setInterval(refreshSOC, 1000);
