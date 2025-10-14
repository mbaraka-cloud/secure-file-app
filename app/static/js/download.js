// Utilitaires front pour pages de téléchargement / listes :
// - confirm() générique via attribut [data-confirm]
// - helpers sélection “tout / rien”
// - ouverture d’un modal HTMX si [data-hx-modal-url] est présent
(function () {
    function ready(fn){document.readyState!=="loading"?fn():document.addEventListener("DOMContentLoaded",fn)}
  
    // Confirmation sur <form data-confirm="..."> et <a data-confirm="...">
    function wireConfirmations(root) {
      root.querySelectorAll("form[data-confirm]").forEach(function (form) {
        form.addEventListener("submit", function (e) {
          const msg = form.getAttribute("data-confirm") || "Confirmer ?";
          if (!confirm(msg)) { e.preventDefault(); }
        });
      });
      root.querySelectorAll("a[data-confirm]").forEach(function (a) {
        a.addEventListener("click", function (e) {
          const msg = a.getAttribute("data-confirm") || "Confirmer ?";
          if (!confirm(msg)) { e.preventDefault(); }
        });
      });
    }
  
    // Sélection en masse (si présents) :
    // <input type="checkbox" id="check-all" data-scope="[name='file_id']">
    function wireSelectAll(root) {
      const master = root.querySelector("#check-all");
      if (!master) return;
      const scope = master.getAttribute("data-scope") || "input[name='file_id']";
      master.addEventListener("change", function () {
        root.querySelectorAll(scope).forEach(function (cb) {
          if (cb instanceof HTMLInputElement && cb.type === "checkbox") cb.checked = master.checked;
        });
      });
    }
  
    // Ouvrir un modal HTMX depuis un bouton/lien :
    // <button data-hx-modal-url="/files/123/confirm-download" data-modal-target="#modal-root">
    function wireHtmxModal(root) {
      root.querySelectorAll("[data-hx-modal-url]").forEach(function (el) {
        el.addEventListener("click", function (e) {
          e.preventDefault();
          const url = el.getAttribute("data-hx-modal-url");
          const target = el.getAttribute("data-modal-target") || "#modal-root";
          const tgt = document.querySelector(target);
          if (!url || !tgt) return;
          // Fallback sans HTMX
          if (!window.htmx) { window.location.href = url; return; }
          htmx.ajax("GET", url, { target: tgt, swap: "innerHTML" });
        });
      });
    }
  
    ready(function () {
      const root = document;
      wireConfirmations(root);
      wireSelectAll(root);
      wireHtmxModal(root);
    });
  })();
  