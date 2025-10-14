// app/static/js/share_bulk_select.js
(function () {
    var STORAGE_KEY = "shareBulk.selected";
    var FORM_ID = "share-bulk-form";
    var LIST_ID = "share-file-list";
  
    // ---- persistance ----
    function loadSet() {
      try {
        var raw = sessionStorage.getItem(STORAGE_KEY);
        var arr = raw ? JSON.parse(raw) : [];
        return new Set((Array.isArray(arr) ? arr : []).map(String));
      } catch (_) { return new Set(); }
    }
    function saveSet(set) {
      try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(Array.from(set))); } catch (_) {}
    }
    var selected = loadSet();
  
    // ---- helpers DOM ----
    function listRoot() { return document.getElementById(LIST_ID); }
    function forEachVisibleRow(fn) {
      var root = listRoot(); if (!root) return;
      root.querySelectorAll('input.row-check[type="checkbox"]').forEach(fn);
    }
    function anyVisibleChecked() {
      var root = listRoot(); if (!root) return false;
      var any = false;
      root.querySelectorAll('input.row-check[type="checkbox"]').forEach(function (cb) {
        if (cb.checked) any = true;
      });
      return any;
    }
    function toggleUncheckVisibility() {
      var root = listRoot(); if (!root) return;
      var wrap = root.querySelector('#uncheck-all-wrapper');
      if (!wrap) return;
      if (anyVisibleChecked()) wrap.classList.remove('hidden');
      else wrap.classList.add('hidden');
    }
    function refreshSelectAllVisual() {
      var root = listRoot(); if (!root) return;
      var all = root.querySelector('#check-all-visible');
      if (!all) return;
      var boxes = root.querySelectorAll('input.row-check[type="checkbox"]');
      if (!boxes.length) { all.checked = false; return; }
      all.checked = Array.from(boxes).every(function (cb) { return cb.checked; });
    }
  
    // ---- appliquer l’état mémorisé aux cases visibles ----
    function applySelectionToView() {
      forEachVisibleRow(function (cb) {
        cb.checked = selected.has(String(cb.value));
      });
      refreshSelectAllVisual();
      toggleUncheckVisibility();
    }
  
    // ---- (re)lier les interactions dans la liste ----
    function bindListInteractions() {
      var root = listRoot();
      if (!root) return;
  
      // “Tout cocher (visible)”
      var selAll = root.querySelector('#check-all-visible');
      if (selAll && !selAll.__bound) {
        selAll.addEventListener('change', function () {
          var willCheck = !!selAll.checked;
          forEachVisibleRow(function (cb) {
            cb.checked = willCheck;
            var id = String(cb.value);
            if (willCheck) selected.add(id);
            else selected.delete(id);
          });
          saveSet(selected);
          toggleUncheckVisibility();
        });
        selAll.__bound = true;
      }
  
      // “Tout décocher (visible)”
      var unSelAll = root.querySelector('#uncheck-all-visible');
      if (unSelAll && !unSelAll.__bound) {
        unSelAll.addEventListener('change', function () {
          // On remet la case elle-même à false (elle sert juste de déclencheur)
          unSelAll.checked = false;
          forEachVisibleRow(function (cb) {
            cb.checked = false;
            selected.delete(String(cb.value));
          });
          saveSet(selected);
          refreshSelectAllVisual();
          toggleUncheckVisibility();
        });
        unSelAll.__bound = true;
      }
  
      // Cases par ligne
      root.querySelectorAll('input.row-check[type="checkbox"]').forEach(function (cb) {
        if (cb.__bound) return;
        cb.addEventListener('change', function () {
          var id = String(cb.value);
          if (cb.checked) selected.add(id); else selected.delete(id);
          saveSet(selected);
          refreshSelectAllVisual();
          toggleUncheckVisibility();
        });
        cb.__bound = true;
      });
    }
  
    // ---- injecter les IDs au submit du formulaire principal ----
    function wireFormSubmit() {
      var form = document.getElementById(FORM_ID);
      if (!form || form.__bound) return;
      form.addEventListener('submit', function () {
        // Nettoyage anciens hidden
        Array.from(form.querySelectorAll('input[type="hidden"].__inj_file_id')).forEach(function (el) {
          el.parentNode.removeChild(el);
        });
        // Injection de tous les IDs sélectionnés (persistants, multi-catégories)
        selected.forEach(function (id) {
          var hid = document.createElement('input');
          hid.type = 'hidden';
          hid.name = 'file_ids';
          hid.value = id;
          hid.className = '__inj_file_id';
          form.appendChild(hid);
        });
      });
      form.__bound = true;
    }
  
    // ---- init ----
    function init() {
      wireFormSubmit();
      applySelectionToView();
      bindListInteractions();
    }
  
    if (document.readyState !== 'loading') init();
    else document.addEventListener('DOMContentLoaded', init);
  
    // Après chaque rendu partiel HTMX de la liste
    document.addEventListener('htmx:afterSwap', function (evt) {
      var t = evt.detail && evt.detail.target;
      if (t && t.id === LIST_ID) {
        applySelectionToView();
        bindListInteractions();
      }
    });
  })();
  