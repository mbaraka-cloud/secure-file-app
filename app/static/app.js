// app/static/app.js — improved robustness

// ----- Catégorie active (accueil) -----
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-cat-btn]');
  if (btn) {
    const hidden = document.getElementById('active-category');
    if (hidden) hidden.value = btn.dataset.category || 'Tous';
  }
});

// Clear suggestions UI when a suggestion button with data-clear-suggestions is clicked
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-clear-suggestions]');
  if (btn) {
    const sug = document.getElementById('suggestions');
    if (sug) sug.innerHTML = '';
  }
});

// Confirm buttons [data-confirm]
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-confirm]');
  if (!btn) return;
  const msg = btn.getAttribute('data-confirm') || 'Confirmer ?';
  if (!confirm(msg)) {
    e.preventDefault();
    e.stopPropagation();
  }
});

// Keep "check all" working after HTMX swaps
document.addEventListener('change', (e) => {
  if (e.target.matches('#share-file-list #check-all, #share-file-list [data-check-all]')) {
    const container = document.getElementById('share-file-list');
    if (!container) return;
    const master = e.target.checked;
    container.querySelectorAll('input[name="file_ids"]').forEach(cb => { cb.checked = master; });
  }
});

// Optional: after any HTMX swap, tidy up stale overlays/popovers
document.addEventListener('htmx:afterSwap', () => {
  // placeholder for future hooks (notifications, etc.)
});
