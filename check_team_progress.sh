#!/bin/bash

BASE=~/soc_project

echo "============================"
echo "🔥 TEAM FINAL CHECK"
echo "============================"

echo ""
echo "👨‍💻 YOU (يوسف):"
[ -f $BASE/outputs/normalized_events.json ] && echo "✔ normalized_events" || echo "❌ normalized_events"
[ -f $BASE/outputs/correlation.json ] && echo "✔ correlation" || echo "❌ correlation"
[ -f $BASE/outputs/ai_analysis.json ] && echo "✔ ai_analysis" || echo "❌ ai_analysis"

echo ""
echo "🖥️ SHARAF (Infra):"
[ -f $BASE/outputs/system_status.json ] && echo "✔ system_status" || echo "❌ system_status"
[ -f $BASE/outputs/firewall_actions.json ] && echo "✔ firewall_actions" || echo "❌ firewall_actions"

echo ""
echo "🌐 HANEN (Network):"
[ -f $BASE/evidence/network_events.json ] && echo "✔ network_events" || echo "❌ network_events"
[ -f $BASE/evidence/network_analysis.json ] && echo "✔ network_analysis" || echo "❌ network_analysis"

echo ""
echo "📊 RAWAN (Incident):"
[ -f $BASE/incidents/incident_ticket.json ] && echo "✔ incident_ticket" || echo "❌ incident_ticket"

echo ""
echo "📈 NOUR (Timeline):"
[ -f $BASE/timeline/timeline.json ] && echo "✔ timeline" || echo "❌ timeline"
[ -f $BASE/timeline/metrics.json ] && echo "✔ metrics" || echo "❌ metrics"

echo ""
echo "🧠 RAHMA (Threat Intel):"
[ -f $BASE/outputs/threat_intel.json ] && echo "✔ threat_intel" || echo "❌ threat_intel"

echo ""
echo "🖥️ KENZY (Monitor):"
[ -d $BASE/frontend ] && echo "✔ frontend" || echo "❌ frontend"
[ -f $BASE/index.html ] && echo "✔ index.html" || echo "❌ index.html"

echo ""
echo "============================"
echo "✅ CHECK DONE"
echo "============================"
