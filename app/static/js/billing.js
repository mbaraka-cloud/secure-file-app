// static/js/billing.js
(function(){
  async function buyCredits(packIndex){
    try{
      const r = await fetch('/stripe/create-checkout-session', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ pack_index: packIndex })
      });
      const ct = r.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        const txt = await r.text().catch(()=> '');
        throw new Error('Réponse inattendue du serveur: ' + r.status);
      }
      const d = await r.json();
      if (d && d.url) {
        window.location = d.url; // -> Stripe Checkout
        return;
      }
      if (d && d.error) {
        alert('Erreur: ' + d.error);
      } else {
        alert('Erreur inconnue.');
      }
    }catch(e){
      console.error(e);
      alert('Erreur réseau. Vérifie la clé STRIPE côté serveur et les CORS/CSP.');
    }
  }

  function attachHandlers(){
    document.querySelectorAll('.js-buy-credits').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-pack-index') || '0', 10);
        buyCredits(idx);
      });
    });
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    attachHandlers();
  } else {
    document.addEventListener('DOMContentLoaded', attachHandlers);
  }
})();
