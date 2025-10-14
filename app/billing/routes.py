import json, re
from flask import request, jsonify, render_template, url_for, current_app, abort
from flask_login import login_required, current_user
import stripe

from app.extensions import db, csrf
from . import billing_bp
from .models import Wallet, CreditTransaction, PaymentSession, DownloadLot
from .utils import estimate_credits_for_lot


def _get_or_create_wallet(user_id: int) -> Wallet:
    w = Wallet.query.filter_by(user_id=user_id).first()
    if not w:
        w = Wallet(user_id=user_id, balance_credits=0)
        db.session.add(w)
        db.session.commit()
    return w


def _mask(s: str) -> str:
    if not s:
        return "(empty)"
    s = s.strip().replace("\r", "").replace("\n", "").strip('"').strip("'")
    if len(s) <= 11:
        return "*" * len(s)
    return s[:7] + "*" * (len(s) - 11) + s[-4:]


def _diagnose_key(raw: str) -> dict:
    """
    Analyse de la clé pour aider au debug sans exposer la valeur.
    Retourne un dict {ok, reason, masked, length, prefix}.
    """
    s = (raw or "").strip().strip('"').strip("'").replace("\r", "").replace("\n", "")
    info = {
        "masked": _mask(s),
        "length": len(s),
        "prefix": s[:8],
        "ok": False,
        "reason": None,
    }
    if not s:
        info["reason"] = "STRIPE_SECRET_KEY manquante."
        return info
    if s.startswith("pk_"):
        info["reason"] = "C'est une *publishable key* (pk_...). Il faut une *secret key* sk_..."
        return info
    if s.startswith("rk_"):
        info["reason"] = "C'est une *restricted key* (rk_...). Utilise une *secret key* sk_..."
        return info
    if not s.startswith("sk_"):
        info["reason"] = "La clé doit commencer par sk_test_ (test) ou sk_live_ (prod)."
        return info
    if "*" in s or "•" in s or "…" in s or "xxxx" in s.lower():
        info["reason"] = "Tu as collé une clé *masquée*. Clique sur “Reveal test key token” dans Stripe et copie TOUTE la clé."
        return info
    # longueur minimale raisonnable après le prefix
    if not re.match(r"^sk_(test|live)_[A-Za-z0-9]{24,}$", s):
        info["reason"] = "Format suspect (probablement tronqué). Re-copie la clé complète depuis le Dashboard."
        return info
    info["ok"] = True
    return info


def _validate_and_set_stripe_key():
    """Valide la clé, configure stripe.api_key. Renvoie (ok, message_ou_None, diag_dict)."""
    raw = current_app.config.get("STRIPE_SECRET_KEY", "")
    diag = _diagnose_key(raw)
    if not diag["ok"]:
        return False, diag["reason"], diag
    stripe.api_key = (raw or "").strip().strip('"').strip("'").replace("\r", "").replace("\n", "")
    return True, None, diag


@billing_bp.route("/wallet", methods=["GET"])
@login_required
def wallet_view():
    wallet = _get_or_create_wallet(current_user.id)
    packs = current_app.config.get(
        "BILLING_CREDIT_PACKS",
        [
            (10, 2000, "eur", "Pack 10"),
            (25, 4500, "eur", "Pack 25"),
            (50, 8000, "eur", "Pack 50"),
        ],
    )
    return render_template("billing/credits_wallet.html", wallet=wallet, packs=packs)


# ---------- DIAGNOSTIC SÛR (ne montre jamais la clé en clair) ----------
@billing_bp.route("/selftest", methods=["GET"])
@login_required
def selftest():
    ok, err, diag = _validate_and_set_stripe_key()
    if not ok:
        return jsonify({"ok": False, "error": err, "diag": diag}), 200
    try:
        acct = stripe.Account.retrieve()
        return jsonify({
            "ok": True,
            "account": {"id": acct.get("id"), "charges_enabled": acct.get("charges_enabled")},
            "diag": diag,
            "tip": "Clé valide. Tu peux lancer un Checkout.",
        }), 200
    except Exception as e:
        return jsonify({"ok": False, "error": f"Appel API Stripe a échoué: {e}", "diag": diag}), 200


@billing_bp.route("/debug_key", methods=["GET"])
@login_required
def debug_key():
    """Expose seulement des infos masquées sur la clé pour comprendre l'erreur."""
    raw = current_app.config.get("STRIPE_SECRET_KEY", "")
    return jsonify(_diagnose_key(raw)), 200
# -----------------------------------------------------------------------


@billing_bp.route("/checkout", methods=["POST"])
@csrf.exempt
@login_required
def checkout_credits():
    ok, err, _diag = _validate_and_set_stripe_key()
    if not ok:
        return jsonify({"error": err, "diag": _diag}), 500

    data = request.get_json(silent=True) or request.form
    try:
        pack_index = int(data.get("pack_index"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid pack_index"}), 400

    packs = current_app.config.get(
        "BILLING_CREDIT_PACKS",
        [
            (10, 2000, "eur", "Pack 10"),
            (25, 4500, "eur", "Pack 25"),
            (50, 8000, "eur", "Pack 50"),
        ],
    )
    if pack_index < 0 or pack_index >= len(packs):
        return jsonify({"error": "Unknown pack"}), 400

    credits, amount, currency, label = packs[pack_index]
    success_url = url_for("billing.checkout_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}"
    cancel_url = url_for("billing.checkout_cancel", _external=True)

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            success_url=success_url,
            cancel_url=cancel_url,
            line_items=[
                {
                    "price_data": {
                        "currency": currency,
                        "product_data": {"name": f"{label} ({credits} crédits)"},
                        "unit_amount": amount,
                    },
                    "quantity": 1,
                }
            ],
            metadata={"user_id": str(current_user.id), "credits": str(credits)},
        )
    except Exception as e:
        return jsonify({"error": f"Erreur Stripe: {e}"}), 500

    ps = PaymentSession(
        user_id=current_user.id,
        stripe_session_id=session["id"],
        amount=amount,
        currency=currency,
        credits_purchased=credits,
        status="pending",
    )
    db.session.add(ps)
    db.session.commit()
    return jsonify({"redirect": session.url})


@billing_bp.route("/checkout/success", methods=["GET"])
@login_required
def checkout_success():
    session_id = request.args.get("session_id")
    return render_template("billing/checkout_success.html", session_id=session_id)


@billing_bp.route("/checkout/cancel", methods=["GET"])
@login_required
def checkout_cancel():
    return render_template("billing/checkout_cancel.html")


@billing_bp.route("/webhook", methods=["POST"])
@csrf.exempt  # webhook externe -> pas de CSRF
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = current_app.config.get("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        abort(500, description="Webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload, sig_header=sig_header, secret=webhook_secret
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        session_id = session["id"]
        payment_intent = session.get("payment_intent")

        ps = PaymentSession.query.filter_by(stripe_session_id=session_id).first()
        if not ps:
            return jsonify({"status": "ignored"}), 200
        if ps.status == "paid":
            return jsonify({"status": "already_processed"}), 200

        # Marquer payé + créditer le wallet (idempotent)
        ps.status = "paid"
        ps.stripe_payment_intent = payment_intent
        db.session.add(ps)

        wallet = _get_or_create_wallet(ps.user_id)
        wallet.balance_credits += ps.credits_purchased

        tx = CreditTransaction(
            user_id=ps.user_id,
            change=ps.credits_purchased,
            reason="topup",
            reference=payment_intent,
            meta_json=json.dumps({"session_id": session_id}),
        )
        db.session.add(tx)
        db.session.add(wallet)
        db.session.commit()

    return jsonify({"status": "ok"}), 200


@billing_bp.route("/estimate", methods=["POST"])
@csrf.exempt
@login_required
def estimate_download_cost():
    data = request.get_json(silent=True) or request.form
    try:
        total_bytes = int(data.get("total_bytes", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid total_bytes"}), 400
    credits = estimate_credits_for_lot(total_bytes)
    return jsonify({"credits": credits})


@billing_bp.route("/debit_and_issue_token", methods=["POST"])
@csrf.exempt
@login_required
def debit_and_issue_token():
    data = request.get_json(silent=True) or request.form
    try:
        total_bytes = int(data.get("total_bytes", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid total_bytes"}), 400

    share_id = data.get("share_id")
    credits_needed = estimate_credits_for_lot(total_bytes)

    wallet = _get_or_create_wallet(current_user.id)
    if wallet.balance_credits < credits_needed:
        return jsonify(
            {
                "error": "insufficient_credits",
                "needed": credits_needed,
                "balance": wallet.balance_credits,
            }
        ), 402

    # Débiter et créer un token de lot
    wallet.balance_credits -= credits_needed
    tx = CreditTransaction(
        user_id=current_user.id,
        change=-credits_needed,
        reason="debit_download",
        reference=None,
        meta_json=json.dumps({"total_bytes": total_bytes, "share_id": share_id}),
    )
    db.session.add(tx)

    ttl = int(current_app.config.get("BILLING_LOT_TOKEN_TTL_MIN", 60))
    lot = DownloadLot.create_with_expiry(
        recipient_user_id=current_user.id,
        total_bytes=total_bytes,
        cost_credits=credits_needed,
        minutes_valid=ttl,
        share_id=int(share_id) if share_id else None,
    )
    db.session.add(lot)
    db.session.commit()

    return jsonify(
        {
            "token": lot.token,
            "expires_at": lot.expires_at.isoformat(),
            "credits_charged": credits_needed,
            "balance": wallet.balance_credits,
        }
    )
