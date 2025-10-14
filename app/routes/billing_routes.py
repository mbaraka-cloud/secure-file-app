# app/routes/billing_routes.py
import json
import hashlib
import time
from typing import Iterable, Tuple

from flask import Blueprint, current_app, request, jsonify, session, url_for
from flask_login import login_required, current_user

from app.extensions import db, csrf, limiter
from app.models.credit_usage import CreditUsage
from app.utils.billing import estimate_for_ids

bp = Blueprint("billing", __name__, url_prefix="/billing")

def _config() -> Tuple[int, int, int]:
    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))
    idem_window = int(current_app.config.get("BILLING_DEBIT_IDEMPOTENCY_WINDOW_SEC", 20))
    return palier_mo, session_fee, idem_window

def _to_int_ids(values: Iterable) -> list[int]:
    if not isinstance(values, (list, tuple)):
        return []
    out, seen = [], set()
    for v in values:
        try:
            iv = int(v)
            if iv > 0 and iv not in seen:
                out.append(iv); seen.add(iv)
        except Exception:
            continue
        if len(out) >= 500:
            break
    return out

def _sanitize_bytes_override(raw):
    if raw is None or raw == "":
        return None
    try:
        v = int(raw)
        if v < 0:
            return None
        return v
    except Exception:
        return None

def _idempotency_guard(label: str, ids: Iterable[int], bytes_total: int, window_sec: int) -> bool:
    sig_src = f"{current_user.id}|{label}|{','.join(map(str, sorted(ids)))}|{int(bytes_total)}"
    sig = hashlib.sha256(sig_src.encode("utf-8")).hexdigest()
    last_sig = session.get("billing_last_sig")
    last_ts = float(session.get("billing_last_ts") or 0)
    now = time.time()
    if last_sig == sig and (now - last_ts) <= max(1, window_sec):
        current_app.logger.info("[billing] Idempotence hit (sig=%s…, %ss)", sig[:8], window_sec)
        return False
    session["billing_last_sig"] = sig
    session["billing_last_ts"] = now
    return True

@bp.post("/estimate")
@login_required
@csrf.exempt
@limiter.limit("40/minute")
def estimate_endpoint():
    data = request.get_json(silent=True) or {}
    file_ids = _to_int_ids(data.get("file_ids") or [])
    bytes_override = _sanitize_bytes_override(data.get("bytes_override"))

    if not file_ids and bytes_override is None:
        return jsonify({"ok": False, "error": "Aucun fichier sélectionné."}), 400

    try:
        palier_mo, session_fee, _ = _config()
        total_bytes, credits = estimate_for_ids(file_ids, palier_mo, session_fee, bytes_override)
    except Exception as e:
        current_app.logger.exception("[billing] /estimate failed")
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({
        "ok": True,
        "total_bytes": int(total_bytes),
        "total_mo": round(total_bytes / (1024 * 1024), 2),
        "credits": int(credits),
        "session_fee": int(session_fee),
        "palier_mo": int(palier_mo),
        "current_credits": int(current_user.credits or 0),
    })

@bp.post("/charge")
@login_required
@csrf.exempt
@limiter.limit("20/minute")
def charge_endpoint():
    data = request.get_json(silent=True) or {}
    file_ids = _to_int_ids(data.get("file_ids") or [])
    bytes_override = _sanitize_bytes_override(data.get("bytes_override"))
    label = str(data.get("label") or "lot")
    meta = {"file_ids": file_ids, "label": label}

    palier_mo, session_fee, idem_window = _config()

    try:
        total_bytes, credits = estimate_for_ids(file_ids, palier_mo, session_fee, bytes_override)
    except Exception as e:
        current_app.logger.exception("[billing] /charge estimate failed")
        return jsonify({"ok": False, "error": str(e)}), 400

    if credits <= 0:
        return jsonify({"ok": False, "error": "Aucun fichier ou taille nulle."}), 400

    if not _idempotency_guard("billing.charge", file_ids, total_bytes, idem_window):
        return jsonify({
            "ok": True,
            "idempotent": True,
            "new_balance": int(current_user.credits or 0),
            "credits_charged": 0,
            "bytes_total": int(total_bytes),
        }), 200

    have = int(current_user.credits or 0)
    if have < credits:
        buy_url = url_for("stripe.buy_page")
        return jsonify({
            "ok": False,
            "reason": "insufficient_credits",
            "need": int(credits),
            "have": have,
            "buy_url": buy_url,
        }), 402

    try:
        current_user.credits = have - int(credits)
        cu = CreditUsage(
            user_id=current_user.id,
            kind="download",
            bytes_total=int(total_bytes),
            credits_cost=int(credits),
            meta_json=json.dumps(meta, ensure_ascii=False),
        )
        db.session.add(cu)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("[billing] charge commit failed")
        return jsonify({"ok": False, "error": "Echec du débit. Réessayez."}), 500

    return jsonify({
        "ok": True,
        "new_balance": int(current_user.credits or 0),
        "credits_charged": int(credits),
        "bytes_total": int(total_bytes),
    })
