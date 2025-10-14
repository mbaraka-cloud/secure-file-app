(function () {
    var form = document.getElementById('upload-form');
    if (!form) return;
  
    var btnUpload = document.getElementById('btn-upload');
    var btnCancel = document.getElementById('btn-cancel');
    var wrap = document.getElementById('up-wrap');
    var bar = document.getElementById('up-bar');
    var pct = document.getElementById('up-percent');
    var stats = document.getElementById('up-stats');
    var eta = document.getElementById('up-eta');
  
    var xhr = null;
    var startedAt = 0;
  
    function fmtBytes(n) {
      if (!n && n !== 0) return '-';
      var u = ['octets','Ko','Mo','Go','To'];
      var i = 0, v = n;
      while (v >= 1024 && i < u.length-1) { v /= 1024; i++; }
      return v.toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
    }
  
    function fmtETA(seconds) {
      if (!isFinite(seconds) || seconds < 0) return 'ETA —';
      var m = Math.floor(seconds / 60);
      var s = Math.floor(seconds % 60);
      if (m > 60) { var h = Math.floor(m / 60); m = m % 60; return 'ETA ' + h + 'h ' + m + 'm'; }
      if (m > 0) return 'ETA ' + m + 'm ' + s + 's';
      return 'ETA ' + s + 's';
    }
  
    function updateProgress(loaded, total) {
      var percent = total ? Math.round((loaded / total) * 100) : 0;
      bar.style.width = percent + '%';
      pct.textContent = percent + '%';
      stats.textContent = fmtBytes(loaded) + ' / ' + fmtBytes(total);
  
      var elapsed = (Date.now() - startedAt) / 1000;
      if (loaded > 0 && elapsed > 0) {
        var rate = loaded / elapsed; // bytes/s
        var remain = total > loaded ? (total - loaded) / rate : 0;
        eta.textContent = fmtETA(remain);
      } else {
        eta.textContent = 'ETA —';
      }
    }
  
    function setUploading(isUploading) {
      if (isUploading) {
        wrap.classList.remove('hidden');
        btnCancel.classList.remove('hidden');
        btnUpload.disabled = true;
      } else {
        btnUpload.disabled = false;
        btnCancel.classList.add('hidden');
      }
    }
  
    btnCancel && btnCancel.addEventListener('click', function () {
      if (xhr) {
        try { xhr.abort(); } catch(_) {}
      }
    });
  
    form.addEventListener('submit', function (ev) {
      // Si aucun fichier sélectionné, laisser le submit normal
      var fileInput = form.querySelector('input[type=file][name=file]');
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) return;
  
      ev.preventDefault();
  
      // Prépare la requête XHR pour avoir les événements de progression d'UPLOAD
      xhr = new XMLHttpRequest();
      xhr.open('POST', form.action, true);
  
      // On demande du JSON (ton endpoint sait déjà répondre JSON si Accept=application/json)
      xhr.setRequestHeader('Accept', 'application/json');
      // IMPORTANT : ne PAS fixer Content-Type ici, laissez XHR le faire pour FormData.
  
      // Progression d'upload
      xhr.upload.onprogress = function (e) {
        if (!e.lengthComputable) return;
        updateProgress(e.loaded, e.total);
      };
  
      xhr.onloadstart = function () {
        startedAt = Date.now();
        setUploading(true);
        updateProgress(0, fileInput.files[0] ? fileInput.files[0].size : 0);
      };
  
      xhr.onerror = function () {
        setUploading(false);
        if (window.showToast) window.showToast('Erreur réseau pendant l’upload.', 'error');
      };
  
      xhr.onabort = function () {
        setUploading(false);
        wrap.classList.add('hidden');
        bar.style.width = '0%';
        pct.textContent = '0%';
        stats.textContent = '0 / 0';
        eta.textContent = 'ETA —';
        if (window.showToast) window.showToast('Upload annulé.', 'warning');
      };
  
      xhr.onload = function () {
        setUploading(false);
        var isJSON = (xhr.getResponseHeader('Content-Type') || '').indexOf('application/json') !== -1;
        if (xhr.status >= 200 && xhr.status < 300) {
          if (isJSON) {
            try {
              var data = JSON.parse(xhr.responseText || '{}');
              if (data.status === 'success') {
                if (window.showToast) window.showToast(data.message || 'Upload réussi ✅', 'success');
                // reset UI
                form.reset();
                // masquer la barre et réinitialiser
                setTimeout(function () {
                  wrap.classList.add('hidden');
                  bar.style.width = '0%';
                  pct.textContent = '0%';
                  stats.textContent = '0 / 0';
                  eta.textContent = 'ETA —';
                }, 600);
  
                // Optionnel : rafraîchir ta liste/accueil si la page contient un fragment HTMX
                // Ici on reste simple : pas de reload automatique pour ne pas déranger l’utilisateur.
                return;
              }
            } catch (e) {/* ignore */}
          }
          // Réponse non-JSON ou statut inattendu -> fallback
          if (window.showToast) window.showToast('Upload terminé.', 'info');
        } else if (xhr.status === 413) {
          if (window.showToast) window.showToast('Fichier trop volumineux (413).', 'danger');
        } else {
          var msg = 'Erreur pendant l’upload.';
          if (isJSON) {
            try {
              var err = JSON.parse(xhr.responseText || '{}');
              if (err && err.message) msg = err.message;
            } catch (_) {}
          }
          if (window.showToast) window.showToast(msg, 'error');
        }
      };
  
      var fd = new FormData(form); // inclut le csrf_token et le fichier
      xhr.send(fd);
    });
  })();
  