// UX léger pour l’upload : affichage nom/taille, disable bouton pendant l’envoi,
// garde tout en POST classique (pas d’AJAX), donc pas de risque de casser la route.
(function () {
    function fmtBytes(bytes) {
      if (!Number.isFinite(bytes)) return "";
      const units = ["o","Ko","Mo","Go","To"];
      let i = 0, n = bytes;
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return n.toFixed(n < 10 && i > 0 ? 1 : 0) + " " + units[i];
    }
  
    function ready(fn){document.readyState!=="loading"?fn():document.addEventListener("DOMContentLoaded",fn)}
    ready(function () {
      const form = document.getElementById("upload-form");
      const input = document.getElementById("file-input");
      const btn = document.getElementById("upload-btn");
      const meta = document.getElementById("file-meta");
      const hint = document.getElementById("file-hint");
  
      if (!form || !input || !btn) return;
  
      input.addEventListener("change", function () {
        const f = input.files && input.files[0];
        if (!f) { meta.classList.add("hidden"); return; }
        meta.textContent = `Sélectionné : ${f.name} (${fmtBytes(f.size)})`;
        meta.classList.remove("hidden");
        // Petit garde-fou si > 2 Go (exemple côté client, non bloquant)
        const maxClient = 2 * 1024 * 1024 * 1024;
        if (f.size > maxClient) {
          hint.textContent = "⚠️ Fichier très volumineux (> 2 Go). L'upload peut être long.";
        } else {
          hint.textContent = "Extensions autorisées larges : images, audio, vidéo, documents, archives, etc.";
        }
      });
  
      form.addEventListener("submit", function () {
        btn.disabled = true;
        btn.textContent = "Envoi en cours…";
      });
    });
  })();
  