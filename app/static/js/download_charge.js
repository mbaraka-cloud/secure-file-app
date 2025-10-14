// app/static/js/download_charge.js
// Branche le paiement par lot AVANT d'appeler ta route de téléchargement.
//
// Requis dans le DOM :
//  - checkboxes: <input type="checkbox" name="file_id" value="123">
//  - bouton: <button id="dl-selected" data-download-url="/download/selected">
//  - (optionnel) bouton "tout télécharger": <button id="dl-all" data-download-url="/download/all" data-bytes-total="1234567">
//
// La route de téléchargement attend typiquement ?ids=1,2,3 (adapte si besoin).

(function () {
    function selectedIds() {
      return Array.from(document.querySelectorAll('input[name="file_id"]:checked'))
        .map(el => parseInt(el.value, 10))
        .filter(Number.isFinite);
    }
  
    async function handleSelected(btn) {
      const ids = selectedIds();
      if (ids.length === 0) { alert("Sélection vide"); return; }
  
      // Estimation
      const est = await Billing.estimate(ids);
      if (!est.ok) { alert(est.error || "Erreur d'estimation"); return; }
  
      if (est.credits > est.current_credits) {
        if (confirm(`Il vous manque ${est.credits - est.current_credits} crédits. Aller acheter ?`)) {
          window.location.href = "/stripe/buy";
        }
        return;
      }
  
      // Débit
      const pay = await Billing.charge(ids);
      if (!pay.ok) { alert(pay.error || "Erreur de paiement"); return; }
  
      // Lancer le téléchargement serveur
      const url = btn.getAttribute("data-download-url") || "/download/selected";
      const target = url + "?ids=" + ids.join(",");
      window.location.href = target;
    }
  
    async function handleAll(btn) {
      const url = btn.getAttribute("data-download-url") || "/download/all";
      const bytesOverride = parseInt(btn.getAttribute("data-bytes-total") || "0", 10) || undefined;
  
      // Si tu as les IDs de tous les fichiers en data-attr, tu peux les passer aussi.
      const idsAttr = btn.getAttribute("data-all-ids");
      const ids = idsAttr ? idsAttr.split(",").map(s => parseInt(s, 10)).filter(Number.isFinite) : [];
  
      const est = await Billing.estimate(ids, bytesOverride);
      if (!est.ok) { alert(est.error || "Erreur d'estimation"); return; }
  
      if (est.credits > est.current_credits) {
        if (confirm(`Il vous manque ${est.credits - est.current_credits} crédits. Aller acheter ?`)) {
          window.location.href = "/stripe/buy";
        }
        return;
      }
  
      const pay = await Billing.charge(ids, bytesOverride);
      if (!pay.ok) { alert(pay.error || "Erreur de paiement"); return; }
  
      window.location.href = url; // ta route "tout télécharger"
    }
  
    function ready(fn){document.readyState!=="loading"?fn():document.addEventListener("DOMContentLoaded",fn)}
    ready(function () {
      const btnSel = document.getElementById("dl-selected");
      if (btnSel) btnSel.addEventListener("click", function (e) {
        e.preventDefault(); handleSelected(btnSel);
      });
  
      const btnAll = document.getElementById("dl-all");
      if (btnAll) btnAll.addEventListener("click", function (e) {
        e.preventDefault(); handleAll(btnAll);
      });
    });
  })();
  