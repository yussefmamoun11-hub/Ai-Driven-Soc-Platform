(function () {
  console.log("Sticky Final State Enabled");

  const CACHE_KEY = "SOC_LAST_FINAL_STATE";
  const originalFetch = window.fetch;

  function valid(data) {
    return data && (
      (Array.isArray(data) && data.length > 0) ||
      (!Array.isArray(data) && typeof data === "object" && Object.keys(data).length > 0)
    );
  }

  function isBadState(data) {
    const s = JSON.stringify(data || {});
    return (
      s.includes('"attempts":0') ||
      s.includes('"alerts":0') ||
      s.includes('MONITORING') ||
      s.includes('waiting') ||
      s.includes('No confirmed attack yet')
    );
  }

  window.fetch = async function(url, options) {
    const res = await originalFetch(url, options);
    if (!String(url).includes(".json")) return res;

    try {
      const data = await res.clone().json();
      const key = String(url).split("?")[0];
      const cache = JSON.parse(localStorage.getItem(CACHE_KEY) || "{}");

      if ((!valid(data) || isBadState(data)) && cache[key]) {
        return new Response(JSON.stringify(cache[key]), {
          status: 200,
          headers: {"Content-Type": "application/json"}
        });
      }

      if (valid(data) && !isBadState(data)) {
        cache[key] = data;
        localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
      }
    } catch(e) {}

    return res;
  };
})();
