# app/routes/stripe_routes.py
import os
import stripe
from flask import Blueprint, current_app, request, jsonify, render_template, url_for
from flask_login import login_required, current_user
from app.extensions import db, csrf
from app.models.user import User
from app.models.purchase import Purchase

bp = Blueprint("stripe", __name__, url_prefix="/stripe")

# Configure Stripe API key dès que possible via l'env (sinon, on la mettra à la volée dans les vues)
_ENV_SK = os.environ.get("STRIPE_SECRET_KEY", "")
if _ENV_SK:
    stripe.api_key = _ENV_SK

def _packs():
    return current_app.config.get(
        "BILLING_CREDIT_PACKS",
        [(10, 2000, "eur", "Pack 10"), (25, 4500, "eur", "Pack 25"), (50, 8000, "eur", "Pack 50")]
    )

def _stripe_keys():
    # Priorité aux variables d’environnement si présentes, sinon config Flask
    sk = os.environ.get("STRIPE_SECRET_KEY") or current_app.config.get("STRIPE_SECRET_KEY", "")
    pk = os.environ.get("STRIPE_PUBLISHABLE_KEY") or current_app.config.get("STRIPE_PUBLISHABLE_KEY", "")
    wh = os.environ.get("STRIPE_WEBHOOK_SECRET") or current_app.config.get("STRIPE_WEBHOOK_SECRET", "")
    return sk, pk, wh

@bp.get("/buy")
@login_required
def buy_page():
    _, publishable_key, _ = _stripe_keys()
    return render_template("payment.html", stripe_pk=publishable_key, packs=_packs())

@bp.post("/create-checkout-session")
@login_required
@csrf.exempt
def create_checkout_session():
    data = request.get_json(silent=True) or {}
    try:
        idx = int(data.get("pack_index", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "pack_index invalide"}), 400

    packs = _packs()
    if idx < 0 or idx >= len(packs):
        return jsonify({"error": "Pack introuvable"}), 400

    credits, amount, currency, label = packs[idx]

    cfg_success = current_app.config.get("STRIPE_SUCCESS_URL") or ""
    cfg_cancel  = current_app.config.get("STRIPE_CANCEL_URL") or ""
    success_url = cfg_success or (url_for("stripe.buy_page", _external=True) + "?success=1&session_id={CHECKOUT_SESSION_ID}")
    cancel_url  = cfg_cancel  or (url_for("stripe.buy_page", _external=True) + "?canceled=1")

    # Assure que stripe.api_key est bien positionnée
    secret_key, publishable_key, _ = _stripe_keys()
    if secret_key:
        stripe.api_key = secret_key

    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": currency,
                    "product_data": {"name": f"Achat de crédits ({label})"},
                    "unit_amount": int(amount),
                },
                "quantity": 1,
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=str(current_user.id),
            customer_email=getattr(current_user, "email", None) or None,
            metadata={
                "user_id": str(current_user.id),
                "credits": str(int(credits)),
                "label": label,
                "pack_index": str(idx),
                "amount_cents": str(int(amount)),
                "currency": currency,
            },
        )

        db.session.add(Purchase(
            session_id=session.id,
            user_id=current_user.id,
            credits=int(credits),
            amount=int(amount),
            currency=currency,
            label=label,
            status="created",
        ))
        db.session.commit()

        current_app.logger.info(f"[STRIPE] Session créée {session.id} pour user#{current_user.id} ({credits} crédits)")

    except Exception as e:
        current_app.logger.exception("Stripe error while creating session")
        return jsonify({"error": str(e)}), 500

    return jsonify({"url": session.url})

@bp.post("/webhook")
@csrf.exempt
def stripe_webhook():
    sk, _, wh_secret = _stripe_keys()
    if sk:
        stripe.api_key = sk

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        if wh_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, wh_secret)
        else:
            event = stripe.Event.construct_from(request.get_json(force=True), stripe.api_key)
    except Exception as e:
        current_app.logger.error(f"[STRIPE] Webhook error: {e}")
        return "Bad payload", 400

    current_app.logger.info(f"[STRIPE] Webhook reçu: {event['type']}")

    if event.type == "checkout.session.completed":
        session = event.data.object
        _credit_from_session_object(session, source="webhook")

    return "", 200

def _credit_from_session_object(session, source="unknown"):
    try:
        sid = session.get("id")
        if not sid:
            current_app.logger.warning(f"[STRIPE] {source}: pas d'id de session")
            return

        payment_status = session.get("payment_status")
        if payment_status != "paid":
            current_app.logger.warning(f"[STRIPE] {source}: session {sid} statut={payment_status}")
            return

        md = session.get("metadata") or {}
        user_id = md.get("user_id")
        credits = int(md.get("credits") or 0)
        label = md.get("label")
        if not user_id or credits <= 0:
            current_app.logger.warning(f"[STRIPE] {source}: metadata incomplète {md}")
            return

        purchase = Purchase.query.filter_by(session_id=sid).first()
        if not purchase:
            purchase = Purchase(
                session_id=sid,
                user_id=int(user_id),
                credits=credits,
                amount=int(session.get("amount_total") or md.get("amount_cents") or 0),
                currency=(session.get("currency") or md.get("currency") or "eur"),
                label=label,
                status="paid",
            )
            db.session.add(purchase)
        else:
            if not purchase.amount:
                purchase.amount = int(session.get("amount_total") or md.get("amount_cents") or 0)
            if not purchase.currency:
                purchase.currency = session.get("currency") or md.get("currency") or purchase.currency
            if not purchase.label and label:
                purchase.label = label
            purchase.status = "paid"

        if purchase.status == "credited":
            current_app.logger.info(f"[STRIPE] {source}: session {sid} déjà créditée")
            db.session.commit()
            return

        user = User.query.get(int(user_id))
        if not user:
            current_app.logger.warning(f"[STRIPE] {source}: user {user_id} introuvable")
            db.session.commit()
            return

        before = int(user.credits or 0)
        user.credits = before + credits
        purchase.status = "credited"
        db.session.commit()

        current_app.logger.info(f"[STRIPE] {source}: +{credits} crédits → User#{user.id} (session {sid}). Total={user.credits}")

    except Exception:
        current_app.logger.exception(f"[STRIPE] {source}: erreur lors du crédit")

@bp.get("/finalize")
@login_required
def finalize_after_return():
    sid = request.args.get("session_id")
    if not sid:
        return jsonify({"ok": False, "error": "session_id manquant"}), 400

    sk, _, _ = _stripe_keys()
    if sk:
        stripe.api_key = sk

    try:
        session = stripe.checkout.Session.retrieve(sid)
    except Exception as e:
        current_app.logger.exception("[STRIPE] Impossible de récupérer la session")
        return jsonify({"ok": False, "error": str(e)}), 400

    _credit_from_session_object(session, source="finalize")
    return jsonify({"ok": True})

@bp.get("/api/me/credits")
@login_required
def api_me_credits():
    return jsonify({"credits": int(current_user.credits or 0)})

@bp.get("/history")
@login_required
def history():
    rows = (Purchase.query
            .filter_by(user_id=current_user.id)
            .order_by(Purchase.created_at.desc())
            .all())
    return render_template("billing/history.html", rows=rows)

@bp.get("/webhook/test")
def webhook_test_get():
    return "webhook OK (GET de test). Le vrai endpoint est POST /stripe/webhook.", 200
