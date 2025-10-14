// app/static/js/admin.js
(function () {
    // --- TOASTS ---------------------------------------------------------------
    var toastWrap = document.getElementById("toast-wrap");
    if (!toastWrap) {
      toastWrap = document.createElement("div");
      toastWrap.id = "toast-wrap";
      toastWrap.className = "fixed top-4 right-4 z-[10000] space-y-2";
      document.body.appendChild(toastWrap);
    }
  
    function showToast(msg, type) {
      var el = document.createElement("div");
      var colors =
        type === "error"
          ? "bg-red-600"
          : type === "warning"
          ? "bg-amber-600"
          : "bg-green-600";
      el.className =
        "text-white " +
        colors +
        " rounded px-3 py-2 shadow transition-opacity";
      el.textContent = msg || "Action effectuée";
      toastWrap.appendChild(el);
      setTimeout(function () {
        el.style.opacity = "0";
        setTimeout(function () {
          try { toastWrap.removeChild(el); } catch (e) {}
        }, 300);
      }, 2500);
    }
  
    // HTMX : écouter les événements déclenchés via HX-Trigger (header)
    document.body.addEventListener("toast", function (ev) {
      // ev.detail = string si HX-Trigger:'{"toast":"..."}'
      var detail = ev.detail;
      if (typeof detail === "string") {
        // si le serveur n'a envoyé que 'toast': 'message'
        showToast(detail, "success");
      } else if (detail && typeof detail === "object") {
        showToast(detail.toast, detail.toast_type || "success");
      } else {
        showToast("Action effectuée", "success");
      }
    });
  
    // --- MODALES --------------------------------------------------------------
    function closeModal(modal) {
      if (!modal) return;
      modal.classList.add("hidden");
      // si la modale venait de #modal-root (HTMX), on nettoie le contenu
      if (modal.id === "modal-root") {
        modal.innerHTML = "";
      }
    }
  
    function clickClosest(el, selector) {
      while (el && el !== document) {
        if (el.matches && el.matches(selector)) return el;
        el = el.parentNode;
      }
      return null;
    }
  
    // délégation : fermeture modales
    document.addEventListener(
      "click",
      function (e) {
        // Bouton qui ouvre une modale locale par id (ex: #new-user-modal)
        var openBtn = clickClosest(e.target, "[data-open]");
        if (openBtn) {
          var targetSel = openBtn.getAttribute("data-open");
          var modal = document.querySelector(targetSel);
          if (modal) {
            modal.classList.remove("hidden");
            modal.classList.add("flex");
          }
          return;
        }
  
        // Fermer via [data-close-modal]
        var btnClose = clickClosest(e.target, "[data-close-modal]");
        if (btnClose) {
          closeModal(btnClose.closest("[data-modal]") || document.getElementById("modal-root"));
          return;
        }
  
        // Fermer en cliquant sur le backdrop
        var backdrop = clickClosest(e.target, "[data-backdrop]");
        if (backdrop) {
          closeModal(backdrop.closest("[data-modal]") || document.getElementById("modal-root"));
          return;
        }
      },
      false
    );
  
    // Fermer auto la modale HTMX après succès 2xx et afficher toast si header présent
    document.body.addEventListener("htmx:afterRequest", function (e) {
      var status = e.detail.xhr ? e.detail.xhr.status : 0;
      if (status >= 200 && status < 300) {
        // si la cible du swap/req est dans une modale → la fermer
        var modalRoot = document.getElementById("modal-root");
        if (modalRoot && modalRoot.innerHTML.trim().length > 0) {
          // Si on vient de mettre à jour la ligne (#user-row-XX), la modale n'a plus de raison d'être
          closeModal(modalRoot);
        }
      }
    });
  
    // Rendre visible un bouton potentiellement "transparent" par CSS
    // (assure qu’il y a toujours une couleur de fond)
    document.querySelectorAll("button").forEach(function (b) {
      if (!b.className.match(/bg-\w+/)) {
        b.classList.add("bg-gray-700", "text-white");
      }
    });
  })();
  