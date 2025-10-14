// app/static/js/stripe_buy.js
(function () {
  function setStatus(msg) {
    var el = document.getElementById("status");
    if (el) el.textContent = msg || "";
  }

  async function createSessionAndRedirect(packIndex) {
    setStatus("Création de la session de paiement…");
    try {
      const r = await fetch("/stripe/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pack_index: packIndex })
      });
      const data = await r.json();
      if (data.error) return setStatus("Erreur: " + data.error);
      if (data.url) window.location.href = data.url;
      else setStatus("Erreur: URL Stripe manquante.");
    } catch (e) {
      setStatus("Erreur réseau: " + (e && e.message ? e.message : e));
    }
  }

  function attachHandlers() {
    document.querySelectorAll(".js-pack").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var idx = parseInt(btn.getAttribute("data-pack-index") || "0", 10);
        createSessionAndRedirect(idx);
      });
    });
  }

  // PLAN B: si on revient de Stripe avec success & session_id, tenter /stripe/finalize
  async function finalizeIfNeeded() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "1" && params.get("session_id")) {
      try {
        const res = await fetch("/stripe/finalize?session_id=" + encodeURIComponent(params.get("session_id")));
        if (!res.ok) {
          setStatus("Finalisation non confirmée (le webhook fera le crédit).");
          return;
        }
        const data = await res.json().catch(() => ({}));
        if (data && data.ok) {
          setStatus("Crédit finalisé. Le solde va se mettre à jour.");
          // ping du badge
          const badge = document.getElementById("credits-badge");
          if (badge) {
            fetch("/stripe/api/me/credits").then(r => r.json()).then(d => {
              if (typeof d.credits === "number") badge.textContent = d.credits;
            }).catch(()=>{});
          }
        } else {
          setStatus("Finalisation non confirmée (le webhook fera le crédit).");
        }
      } catch (e) {
        setStatus("Finalisation non confirmée (le webhook fera le crédit).");
      }
    }
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    attachHandlers(); finalizeIfNeeded();
  } else {
    document.addEventListener("DOMContentLoaded", function () {
      attachHandlers(); finalizeIfNeeded();
    });
  }
})();
