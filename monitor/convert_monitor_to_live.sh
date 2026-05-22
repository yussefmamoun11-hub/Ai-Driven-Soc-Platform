#!/bin/bash
set -e

# -------------------------------------------------------
# Dynamic project path detection
# -------------------------------------------------------
if [ -f "/home/mamoun/soc_project/index.html" ]; then
  BASE="/home/mamoun/soc_project"
elif [ -f "$HOME/soc_project/index.html" ]; then
  BASE="$HOME/soc_project"
else
  echo "[!] Could not find soc_project with index.html"
  exit 1
fi

INDEX="$BASE/index.html"
DATA="$BASE/data"
BACKUP_DIR="$BASE/backups"
TS="$(date +%Y%m%d_%H%M%S)"
BACKUP="$BACKUP_DIR/index.html.$TS.bak"
JS_FILE="$BASE/live_binding.js"

mkdir -p "$DATA" "$BACKUP_DIR"

if [ ! -f "$INDEX" ]; then
  echo "[!] Missing index.html at $INDEX"
  exit 1
fi

cp "$INDEX" "$BACKUP"
echo "[✓] Backup created: $BACKUP"
echo "[i] Using BASE: $BASE"

# -------------------------------------------------------
# 1) Create fallback JSON files if missing
# -------------------------------------------------------
create_if_missing() {
  local path="$1"
  local content="$2"
  if [ ! -f "$path" ] || [ ! -s "$path" ]; then
    echo "$content" > "$path"
    echo "[✓] Created fallback: $path"
  else
    echo "[i] Exists: $path"
  fi
}

create_if_missing "$DATA/network_packets.json" '[]'
create_if_missing "$DATA/overview.json" '{}'
create_if_missing "$DATA/structured_events.json" '[]'
create_if_missing "$DATA/incident_status.json" '{}'
create_if_missing "$DATA/metrics.json" '{}'
create_if_missing "$DATA/threat_intel.json" '{}'
create_if_missing "$DATA/containment_status.json" '{}'
create_if_missing "$DATA/timeline.json" '[]'
create_if_missing "$DATA/evidence_status.json" '{}'
create_if_missing "$DATA/system_status.json" '{}'
create_if_missing "$DATA/rule_status.json" '{}'
create_if_missing "$DATA/baseline_comparison.json" '{}'
create_if_missing "$DATA/runtime_info.json" '{}'

# -------------------------------------------------------
# 2) Write live binding JS
# -------------------------------------------------------
cat > "$JS_FILE" <<'EOF'
/* SOC Monitor Live Binding Layer v2 */
(function () {
  const POLL_MS = 3000;

  const FILES = {
    detection: 'data/detection_results.json',
    alerts: 'data/alerts.json',
    ai: 'data/ai_analysis.json',
    correlation: 'data/correlation.json',
    privilege: 'data/privilege_activity.json',
    packets: 'data/network_packets.json',
    overview: 'data/overview.json',
    events: 'data/structured_events.json',
    incident: 'data/incident_status.json',
    metrics: 'data/metrics.json',
    threat: 'data/threat_intel.json',
    contain: 'data/containment_status.json',
    timeline: 'data/timeline.json',
    evidence: 'data/evidence_status.json',
    sources: 'data/system_status.json',
    rules: 'data/rule_status.json',
    baseline: 'data/baseline_comparison.json',
    runtime: 'data/runtime_info.json'
  };

  function el(id) { return document.getElementById(id); }

  function setText(id, value, fallback = 'N/A') {
    const node = el(id);
    if (!node) return;
    node.textContent = value === undefined || value === null || value === '' ? fallback : String(value);
  }

  function setPill(id, value) {
    const node = el(id);
    if (!node) return;
    const v = String(value || 'N/A').toUpperCase();
    node.textContent = v;

    node.classList.remove('pill-g','pill-r','pill-a','pill-c','pill-p');

    if (['CRITICAL','HIGH','OPEN','ACTIVE','TRIGGERED'].includes(v)) node.classList.add('pill-r');
    else if (['MEDIUM','INVESTIGATING','PENDING','PARTIAL','WARNING'].includes(v)) node.classList.add('pill-a');
    else if (['LOW','READY','LIVE','OK','ENABLED','HEALTHY'].includes(v)) node.classList.add('pill-g');
    else node.classList.add('pill-c');
  }

  function shortTs(ts) {
    if (!ts) return '--:--:--';
    const s = String(ts);
    const m = s.match(/T(\d{2}:\d{2}:\d{2})/);
    if (m) return m[1];
    return s.slice(11, 19) || s;
  }

  function latestTimestamp(...items) {
    const vals = [];
    for (const item of items) {
      if (!item) continue;
      if (Array.isArray(item)) {
        item.forEach(x => { if (x && x.timestamp) vals.push(x.timestamp); });
      } else {
        if (item.timestamp) vals.push(item.timestamp);
        if (item.generated_at) vals.push(item.generated_at);
      }
    }
    vals.sort();
    return vals.length ? vals[vals.length - 1] : null;
  }

  async function loadJson(path) {
    try {
      const res = await fetch(path, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return null;
    }
  }

  function arr(v) { return Array.isArray(v) ? v : []; }
  function first(v) { return Array.isArray(v) ? (v[0] || null) : (v || null); }

  function extractAttackerIp(ai, corr, alerts, detection, privilege, threat) {
    if (ai && ai.attacker_ip) return ai.attacker_ip;
    if (corr && corr.attacker_ip) return corr.attacker_ip;
    const a0 = first(alerts);
    if (a0 && a0.src_ip) return a0.src_ip;
    const d0 = arr(detection).find(x => x && x.src_ip && x.src_ip !== 'unknown');
    if (d0) return d0.src_ip;
    const p0 = first(privilege);
    if (p0 && p0.src_ip) return p0.src_ip;
    if (threat && threat.attacker_ip) return threat.attacker_ip;
    return 'N/A';
  }

  function extractIncidentId(corr, incident, alerts) {
    if (corr && corr.correlated_incident) return corr.correlated_incident;
    if (incident && incident.incident_id) return incident.incident_id;
    const a0 = first(alerts);
    if (a0 && a0.incident_id) return a0.incident_id;
    return 'INC-UNKNOWN';
  }

  function countFailed(detection) {
    return arr(detection).filter(e => e && e.event_type === 'failed_login').length;
  }

  function countSuccessful(detection) {
    return arr(detection).filter(e => e && e.event_type === 'successful_login').length;
  }

  function updateTopMetrics(ai, alerts, detection, corr) {
    const failed = countFailed(detection);
    const alertCount = arr(alerts).length || (corr ? 1 : 0);
    const sev = (ai && ai.threat_level) || (corr && corr.severity) || 'UNKNOWN';
    const incident = (corr && corr.correlated_incident) || 'N/A';

    const sevNode = document.querySelector('.met-r .met-value');
    if (sevNode) sevNode.textContent = String(sev).toUpperCase();

    const sevSub = document.querySelector('.met-r .met-sub');
    if (sevSub) sevSub.textContent = `${String(sev).toUpperCase()} · ${incident}`;

    setText('mc-att', failed, '0');
    setText('mc-alerts', alertCount, '0');
    setText('q-alerts', alertCount, '0');
    setText('q-att', failed, '0');
  }

  function updateAlert(alerts, ai, corr, attackerIp, incidentId) {
    const a0 = first(alerts);

    setText('alert-inc-id', `⬡ ${incidentId}`);
    setText('alert-title',
      (a0 && (a0.title || a0.description)) ||
      (ai && ai.threat_narrative) ||
      (corr && corr.verdict) ||
      'No alert data yet'
    );
    setText('alert-src', `${attackerIp}`);
    setPill('alert-sev-tag',
      (a0 && a0.severity) ||
      (corr && corr.severity) ||
      (ai && ai.threat_level) ||
      'UNKNOWN'
    );
    setPill('alert-status-tag',
      (a0 && a0.status) ||
      (corr && corr.severity === 'critical' ? 'INVESTIGATING' : 'OPEN')
    );
  }

  function updateAI(ai, attackerIp) {
    if (!ai) return;

    setText('ai-src', attackerIp);
    setPill('ai-sev', ai.threat_level || 'UNKNOWN');

    let pattern = 'Threat Activity';
    if (ai.attack_stages_detected) {
      if (ai.attack_stages_detected.privilege_abuse) pattern = 'Privilege Abuse Attempt';
      else if (ai.attack_stages_detected.sensitive_access) pattern = 'Sensitive Access';
      else if (ai.attack_stages_detected.post_login_activity) pattern = 'Post-Login Activity';
      else if (ai.attack_stages_detected.successful_login) pattern = 'Unauthorized Access';
      else if (ai.attack_stages_detected.brute_force) pattern = 'SSH Brute Force';
    }
    setText('ai-pattern', pattern);

    if (Array.isArray(ai.mitre_techniques_observed) && ai.mitre_techniques_observed.length) {
      setText('ai-mitre', ai.mitre_techniques_observed.join(', '));
    }
  }

  function updateIncident(corr, incident, incidentId) {
    const sev = (corr && corr.severity) || (incident && incident.severity) || 'UNKNOWN';
    const status = (incident && incident.status) || (sev === 'critical' ? 'INVESTIGATING' : 'OPEN');

    setText('inc-id-big', incidentId);
    setText('inc-type',
      (corr && corr.verdict === 'CONFIRMED MULTI-STAGE ATTACK') ? 'Multi-Stage Attack' :
      (corr && corr.verdict === 'CORRELATED ATTACK CHAIN') ? 'Correlated Attack Chain' :
      (incident && incident.title) || 'Security Incident'
    );
    setPill('inc-sev', sev);
    setPill('inc-status', status);
    setText('inc-assignee', (incident && incident.assignee) || 'SOC Team');
    setText('inc-opened', shortTs((corr && corr.timestamp) || (incident && incident.timestamp)));
  }

  function updateThreat(threat, attackerIp) {
    setText('ti-ip', attackerIp);
    const rep = (threat && (threat.reputation || threat.label || threat.status)) || 'SUSPICIOUS HOST';
    const repNode = document.getElementById('ti-rep');
    if (repNode) repNode.textContent = rep;
    setText('ti-summary',
      (threat && (threat.summary || threat.note || threat.context)) ||
      `Observed suspicious progression from ${attackerIp}.`
    );
  }

  function updateContainment(contain, ai) {
    setPill('contain-fw', (contain && contain.firewall_status) || 'ENABLED');
    setPill('contain-f2b', (contain && contain.fail2ban_status) || 'ACTIVE');
    setPill('contain-action',
      (contain && contain.action) ||
      ((ai && ai.auto_containment_triggered) ? 'TRIGGERED' : 'PENDING')
    );
    setText('contain-result',
      (contain && contain.result) ||
      ((ai && ai.auto_containment_triggered) ? 'Containment recommended' : 'Awaiting approval')
    );
  }

  function updateDetectionCounters(detection) {
    const failed = countFailed(detection);
    setText('baseline-cur', failed, '0');
    setText('rh1', `×${failed}`, '×0');
  }

  function updateTimeline(timeline, detection, ai, privilege, corr) {
    const box = document.querySelector('.timeline');
    if (!box) return;

    const incoming = arr(timeline);
    if (incoming.length) {
      box.innerHTML = incoming.slice(0, 8).map(item => `
        <div class="tl">
          <div class="tl-dot ${item.live ? 'tld-live' : (item.done ? 'tld-done' : 'tld-pend')}"></div>
          <div class="tl-body">
            <div class="tl-ts">${shortTs(item.timestamp || item.ts || item.time || '')}</div>
            <div class="tl-text">${item.text || item.description || 'Timeline event'}</div>
          </div>
        </div>
      `).join('');
      return;
    }

    const failed = countFailed(detection);
    const success = countSuccessful(detection);
    const priv0 = first(privilege);

    const rows = [];
    if (failed > 0) rows.push({ts: latestTimestamp(detection), text: `${failed} failed SSH login attempts observed`, cls: 'tld-done'});
    if (success > 0) rows.push({ts: latestTimestamp(detection), text: `${success} successful login event(s) confirmed`, cls: 'tld-done'});
    if (ai && ai.attack_stages_detected && ai.attack_stages_detected.post_login_activity) rows.push({ts: ai.timestamp, text: 'Post-login activity visible on host', cls: 'tld-done'});
    if (ai && ai.attack_stages_detected && ai.attack_stages_detected.sensitive_access) rows.push({ts: ai.timestamp, text: 'Sensitive resource access observed', cls: 'tld-live'});
    if (priv0) rows.push({ts: priv0.timestamp, text: priv0.description || 'Privilege abuse attempt observed', cls: 'tld-live'});
    if (corr && corr.correlated_incident) rows.push({ts: corr.timestamp, text: `${corr.correlated_incident} correlated on Ubuntu-side outputs`, cls: 'tld-live'});

    if (!rows.length) return;

    box.innerHTML = rows.map(item => `
      <div class="tl">
        <div class="tl-dot ${item.cls}"></div>
        <div class="tl-body">
          <div class="tl-ts">${shortTs(item.ts)}</div>
          <div class="tl-text">${item.text}</div>
        </div>
      </div>
    `).join('');
  }

  function updateEventTable(events, detection, attackerIp) {
    const tbody = document.querySelector('.evtbl tbody');
    if (!tbody) return;

    const src = arr(events).length ? arr(events) : arr(detection);
    if (!src.length) return;

    tbody.innerHTML = src.slice(0, 10).map(e => {
      const sev = String(e.severity || 'LOW').toUpperCase();
      const sevClass = ['HIGH','CRITICAL'].includes(sev) ? 'sev-h' : (sev === 'MEDIUM' ? 'sev-m' : 'sev-l');
      return `
        <tr>
          <td style="font-family:var(--mono);font-size:9px;color:var(--t3)">${shortTs(e.timestamp)}</td>
          <td style="font-family:var(--mono);font-size:9px;color:var(--c)">${e.src_ip || attackerIp}</td>
          <td style="font-family:var(--mono);font-size:9px">${e.dst_ip || 'Ubuntu Host'}</td>
          <td style="font-family:var(--mono);font-size:9px;color:var(--t1)">${e.description || e.event_type || 'Event'}</td>
          <td><span class="sev ${sevClass}">${sev}</span></td>
        </tr>
      `;
    }).join('');
  }

  function updatePacketTable(packets, attackerIp) {
    const tbody = document.getElementById('pkt-tbody');
    if (!tbody) return;

    const rows = arr(packets);
    if (!rows.length) return;

    tbody.innerHTML = rows.slice(0, 12).map((p, i) => `
      <tr class="r-ssh">
        <td class="td-no">${i + 1}</td>
        <td class="td-ts">${shortTs(p.timestamp || p.ts)}</td>
        <td class="td-src">${p.src_ip || attackerIp}</td>
        <td class="td-dst">${p.dst_ip || 'N/A'}</td>
        <td><span class="proto proto-ssh">${p.proto || 'SSH'}</span></td>
        <td class="td-len">${p.len || '0'}</td>
        <td class="td-info">${p.info || p.description || 'Packet event'}</td>
      </tr>
    `).join('');
  }

  function updateTicker(attackerIp, incidentId, ai, detection) {
    const ticker = document.getElementById('ticker');
    if (!ticker) return;
    const fails = countFailed(detection);
    const sev = (ai && ai.threat_level) || 'UNKNOWN';

    ticker.innerHTML = `
      <span class="ticker-item">⬡ ATTACKER ${attackerIp}</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">${incidentId} ACTIVE — Severity: ${sev}</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">Failed logins: ${fails}</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">Ubuntu server outputs live</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">Monitor polling every ${POLL_MS / 1000}s</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">⬡ ATTACKER ${attackerIp}</span>
      <span class="ticker-sep">·</span>
      <span class="ticker-item">${incidentId} ACTIVE — Severity: ${sev}</span>
    `;
  }

  function updateFreshness(ts) {
    if (!ts) return;
    let note = document.getElementById('freshness-note');
    const bar = document.querySelector('.statusbar');
    if (!bar) return;

    if (!note) {
      note = document.createElement('div');
      note.id = 'freshness-note';
      note.className = 'sb-item';
      bar.insertBefore(note, bar.firstChild);
    }

    note.innerHTML = `DATA <span class="sb-val" style="margin-left:4px">${shortTs(ts)}</span>`;
    ['f1-ts','f2-ts','f3-ts','f4-ts'].forEach(id => setText(id, shortTs(ts)));
  }

  async function refreshDashboard() {
    const [
      detection, alerts, ai, correlation, privilege, packets, overview, events,
      incident, metrics, threat, contain, timeline, evidence, sources, rules,
      baseline, runtime
    ] = await Promise.all([
      loadJson(FILES.detection),
      loadJson(FILES.alerts),
      loadJson(FILES.ai),
      loadJson(FILES.correlation),
      loadJson(FILES.privilege),
      loadJson(FILES.packets),
      loadJson(FILES.overview),
      loadJson(FILES.events),
      loadJson(FILES.incident),
      loadJson(FILES.metrics),
      loadJson(FILES.threat),
      loadJson(FILES.contain),
      loadJson(FILES.timeline),
      loadJson(FILES.evidence),
      loadJson(FILES.sources),
      loadJson(FILES.rules),
      loadJson(FILES.baseline),
      loadJson(FILES.runtime)
    ]);

    const attackerIp = extractAttackerIp(ai, correlation, alerts, detection, privilege, threat);
    const incidentId = extractIncidentId(correlation, incident, alerts);
    const latestTs = latestTimestamp(
      detection, alerts, ai, correlation, privilege, packets, overview, events,
      incident, metrics, threat, contain, timeline, evidence, sources, rules,
      baseline, runtime
    );

    updateTopMetrics(ai, alerts, detection, correlation);
    updateAlert(alerts, ai, correlation, attackerIp, incidentId);
    updateAI(ai, attackerIp);
    updateIncident(correlation, incident, incidentId);
    updateThreat(threat, attackerIp);
    updateContainment(contain, ai);
    updateDetectionCounters(detection);
    updateTimeline(timeline, detection, ai, privilege, correlation);
    updateEventTable(events, detection, attackerIp);
    updatePacketTable(packets, attackerIp);
    updateTicker(attackerIp, incidentId, ai, detection);
    updateFreshness(latestTs);

    if (runtime && runtime.url) {
      document.title = `SOC NEXUS — ${runtime.current_ip || 'Server'}:${runtime.port || ''}`;
    }
  }

  function boot() {
    refreshDashboard();
    setInterval(refreshDashboard, POLL_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
EOF

python3 - <<PY
from pathlib import Path

index = Path("$INDEX")
html = index.read_text(encoding="utf-8", errors="ignore")
tag = '<script src="live_binding.js"></script>'

if tag in html:
    print("[i] live_binding.js already linked")
else:
    if "</body>" in html:
        html = html.replace("</body>", f'  {tag}\n</body>')
        index.write_text(html, encoding="utf-8")
        print("[✓] Injected live_binding.js into index.html")
    else:
        print("[!] Could not find </body> in index.html")
        raise SystemExit(1)
PY

if [ -f "$BASE/sync_outputs_to_data.sh" ]; then
  bash "$BASE/sync_outputs_to_data.sh" || true
fi

if systemctl list-unit-files | grep -q '^soc-monitor.service'; then
  sudo systemctl restart soc-monitor.service || true
  echo "[✓] Restarted soc-monitor.service"
fi

echo
echo "============================================"
echo "DONE"
echo "============================================"
echo "Using BASE: $BASE"
echo
echo "Next:"
echo "1) Open current URL:"
if [ -f "$BASE/current_url.txt" ]; then
  cat "$BASE/current_url.txt"
else
  echo "current_url.txt not found"
fi
echo
echo "2) Refresh browser with Ctrl+F5"
echo
echo "3) Validate binding:"
if [ -f "$BASE/validate_frontend_binding.sh" ]; then
  echo "   bash $BASE/validate_frontend_binding.sh"
fi
echo "============================================"
