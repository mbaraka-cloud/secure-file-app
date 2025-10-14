// app/static/js/shared.js
(function(){
  function qsa(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }
  function qs(sel, root){ return (root||document).querySelector(sel); }

  var master   = null;
  var listEl   = null;
  var pill     = null;
  var btnMulti = null;
  var dlBadge  = null;

  // ===== Persistance sélection =====
  var KEY = 'selected_file_ids';
  function loadSel(){
    try { return new Set(JSON.parse(sessionStorage.getItem(KEY) || '[]')); }
    catch(e){ return new Set(); }
  }
  function saveSel(set){
    try { sessionStorage.setItem(KEY, JSON.stringify(Array.from(set))); }
    catch(e){}
  }
  function applySel(){
    var sel = loadSel();
    rows().forEach(function(cb){ cb.checked = sel.has(cb.value); });
    refreshMaster();
    renderEstimateRealtime();
  }

  // --- Mini toasts
  function toast(msg, type){
    var root = document.getElementById('toast-root');
    if(!root){ if(window.console) console.log("[toast]", msg); return; }
    var el = document.createElement('div');
    el.className = 'toast ' + (type==='success'?'bg-green-700':type==='danger' || type==='error'?'bg-red-700':type==='warning'?'bg-yellow-600':'bg-gray-800');
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(function(){ el.style.opacity='0'; el.style.transition='opacity .3s'; }, 3200);
    setTimeout(function(){ if(el.parentNode) root.removeChild(el); }, 3600);
  }

  function rows(){ return qsa('#shared-list input.row-check[type="checkbox"]'); }

  // ===== Sélecteur "Tout cocher" =====
  function refreshMaster(){
    master = qs('#check-all');
    if(!master) return;
    var list = rows();
    var on = list.filter(function(cb){return cb.checked}).length;
    if(list.length===0 || on===0){ master.indeterminate=false; master.checked=false; }
    else if(on===list.length){    master.indeterminate=false; master.checked=true; }
    else {                        master.indeterminate=true;  master.checked=false; }
  }

  function bindMaster(){
    master = qs('#check-all');
    if(!master) return;
    master.addEventListener('change', function(){
      var v = !!master.checked;
      var sel = loadSel();
      rows().forEach(function(cb){
        cb.checked = v;
        if (v) sel.add(cb.value); else sel.delete(cb.value);
      });
      saveSel(sel);
      refreshMaster();
      renderEstimateRealtime();
    }, false);
  }

  function bindList(){
    listEl = qs('#shared-list');
    if (!listEl) return;
    listEl.addEventListener('change', function(e){
      var t = e.target || e.srcElement;
      if(t && t.classList && t.classList.contains('row-check')){
        var sel = loadSel();
        if (t.checked) sel.add(t.value); else sel.delete(t.value);
        saveSel(sel);
        refreshMaster();
        renderEstimateRealtime();
      }
    }, false);
  }

  // ===== Estimation côté client (temps réel) =====
  pill = qs('#est-pill');
  dlBadge = qs('#dl-counter');

  function humanSize(bytes){
    if (bytes < 1024) return bytes + ' o';
    var kb = bytes/1024;      if (kb < 1024) return kb.toFixed(1) + ' Ko';
    var mb = kb/1024;         if (mb < 1024) return mb.toFixed(1) + ' Mo';
    var gb = mb/1024;         return gb.toFixed(2) + ' Go';
  }
  function selectedIds(){
    return rows().filter(function(cb){ return cb.checked; }).map(function(cb){ return cb.value; });
  }
  function selectedBytes(){
    return rows().reduce(function(sum, cb){
      if (cb.checked){
        var b = parseInt(cb.getAttribute('data-bytes') || '0', 10);
        if (!isNaN(b) && b > 0) sum += b;
      }
      return sum;
    }, 0);
  }
  function estimateCredits(totalBytes){
    if (!totalBytes || totalBytes <= 0) return 0;
    var palierMo = Math.max(window.APP_PALIER_MO || 500, 1);
    var sessionFee = parseInt(window.APP_SESSION_FEE || 1, 10);
    var totalMo = totalBytes / (window.APP_BYTES_PER_MO || (1024*1024));
    var extra = Math.floor(totalMo / palierMo);
    return sessionFee + extra;
  }
  function renderEstimateRealtime(){
    if (!pill) pill = qs('#est-pill');
    if (!pill) return;
    var ids = selectedIds();
    if (!ids.length){
      pill.classList.add('hidden');
      pill.textContent = '';
      return;
    }
    var bytes   = selectedBytes();
    var credits = estimateCredits(bytes);
    pill.textContent = 'Sélection: ' + ids.length + ' • ' + humanSize(bytes) + ' • ' +
                       credits + ' crédit' + (credits>1?'s':'');
    pill.classList.remove('hidden');
  }

  // ===== Téléchargements séparés (conservé tel quel) =====
  function triggerDownload(url){
    var a = document.createElement('a');
    a.href = url;
    a.rel = 'noopener';
    a.target = '_blank';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ document.body.removeChild(a); }, 1000);
  }

  function updateCounter(i, total){
    if(!dlBadge) dlBadge = qs('#dl-counter');
    if(!dlBadge) return;
    dlBadge.textContent = 'Téléchargements : ' + i + ' / ' + total;
    dlBadge.classList.remove('hidden');
    if (i >= total){
      setTimeout(function(){ dlBadge.classList.add('hidden'); }, 2500);
    }
  }

  var running = false; // anti double-clic
  function startBatch(links){
    if (!links || !links.length) return;
    if (running) { return; }
    running = true;

    var i = 0;
    var total = links.length;
    updateCounter(0, total);
    toast('Lancement de ' + total + ' téléchargement(s)…', 'info');

    (function next(){
      triggerDownload(links[i]);
      i++;
      updateCounter(i, total);
      if (i < total){
        setTimeout(next, 600); // tempo pour éviter les blocages navigateurs
      } else {
        running = false;
        toast('Téléchargements lancés ('+total+').', 'success');
      }
    })();
  }

  function fetchLinksAndDownload(){
    var ids = selectedIds();
    if (!ids.length){
      toast('Veuillez sélectionner au moins un fichier.', 'warning');
      return;
    }
    if (running) return;

    var params = new URLSearchParams();
    params.set('ids', ids.join(','));

    fetch('/shared/download/selected/links?' + params.toString(), {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    })
    .then(function(res){
      return res.json().then(function(data){ return { status: res.status, data: data }; });
    })
    .then(function(resObj){
      var status = resObj.status, data = resObj.data || {};
      if (status === 200 && data.ok && Array.isArray(data.links)){
        startBatch(data.links);
        return;
      }
      if (status === 402 && data.reason === 'insufficient_credits'){
        var go = confirm('Crédits insuffisants (' + (data.have||0) + ' / requis ' + (data.needed||'?') + ').\nAller acheter des crédits ?');
        if (go) window.location.href = data.buy_url || '/stripe/buy';
        return;
      }
      toast('Impossible de lancer les téléchargements séparés. Code: ' + status, 'error');
    })
    .catch(function(err){
      console.error(err);
      toast('Erreur réseau lors de la récupération des liens.', 'error');
    });
  }

  btnMulti = qs('#btn-multi');
  if (btnMulti){
    btnMulti.addEventListener('click', fetchLinksAndDownload, false);
  }

  // ===== Init + support HTMX =====
  function init(){
    bindMaster();
    bindList();
    applySel();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, false);
  } else {
    init();
  }

  // Quand HTMX remplace la liste (#files-list -> partiel), on réinitialise et on ré-applique la sélection
  document.addEventListener('htmx:load', function(){
    init();
  }, false);
})();
