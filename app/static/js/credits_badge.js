// app/static/js/credits_badge.js
(function () {
    const badge = document.getElementById("credits-badge");
    if (!badge) return;
  
    let tries = 0;
    const maxTries = 20;            // ~60s si intervalle 3s
    const intervalMs = 3000;
  
    const url = new URL(window.location.href);
    const shouldRefresh =
      url.searchParams.get("success") === "1" || url.pathname.indexOf("/stripe/") !== -1;
  
    if (!shouldRefresh) return;
  
    async function tick() {
      tries += 1;
      try {
        const r = await fetch("/stripe/api/me/credits", { credentials: "same-origin" });
        if (r.ok) {
          const data = await r.json();
          if (typeof data.credits === "number") {
            badge.textContent = data.credits;
            if (tries >= maxTries) clearInterval(timer);
          }
        }
      } catch (_e) {
        // silent
      }
      if (tries >= maxTries) clearInterval(timer);
    }
  
    const timer = setInterval(tick, intervalMs);
    tick(); // premier appel immédiat
  })();
  