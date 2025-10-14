// app/static/js/billing_batch.js
// Helpers pour estimer et facturer un "lot" de fichiers par IDs.
//
// Exemple d'utilisation :
//
//   const ids = [12, 34, 56]; // tes file_ids (entiers)
//   const est = await Billing.estimate(ids);
//   if (!est.ok) { alert(est.error || "Erreur estimate"); return; }
//   if (est.credits > est.current_credits) {
//     if (confirm(`Il manque ${est.credits - est.current_credits} crédits. Aller acheter ?`)) {
//       window.location.href = est.buy_url || "/stripe/buy";
//     }
//     return;
//   }
//   const pay = await Billing.charge(ids);
//   if (pay.ok) {
//     // lancer ton téléchargement existant (ex: window.location.href = "/download?token=...";)
//   }
//
// NOTE: si tu connais le total_bytes côté client (ex: data-size), tu peux passer {bytesOverride: ...}

window.Billing = (function () {
    async function _post(url, payload) {
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(payload || {})
      });
      const ct = r.headers.get("content-type") || "";
      if (!ct.includes("application/json")) {
        const t = await r.text();
        throw new Error(`HTTP ${r.status}: ${t}`);
      }
      const data = await r.json();
      if (!r.ok) throw new Error(data && data.error ? data.error : `HTTP ${r.status}`);
      return data;
    }
  
    async function estimate(fileIds, bytesOverride) {
      return _post("/billing/estimate", { file_ids: fileIds || [], bytes_override: bytesOverride });
    }
  
    async function charge(fileIds, bytesOverride) {
      return _post("/billing/charge", { file_ids: fileIds || [], bytes_override: bytesOverride });
    }
  
    return { estimate, charge };
  })();
  