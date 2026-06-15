async function safeFetch(path) {
    try {
        const res = await fetch(path);

        const text = await res.text();

        try {
            return JSON.parse(text);
        } catch (e) {
            return { error: "Invalid JSON in " + path, raw: text };
        }

    } catch (err) {
        return { error: err.message };
    }
}

async function updateDashboard() {

    const alerts = await safeFetch("/outputs/alerts.json");
    const ai = await safeFetch("/outputs/ai_analysis.json");
    const corr = await safeFetch("/outputs/correlation.json");
    const priv = await safeFetch("/outputs/privilege_activity.json");

    document.getElementById("alerts").textContent =
        JSON.stringify(alerts, null, 2);

    document.getElementById("ai").textContent =
        JSON.stringify(ai, null, 2);

    document.getElementById("corr").textContent =
        JSON.stringify(corr, null, 2);

    document.getElementById("priv").textContent =
        JSON.stringify(priv, null, 2);
}

updateDashboard();
setInterval(updateDashboard, 5000);
