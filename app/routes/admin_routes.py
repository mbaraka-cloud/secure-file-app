# app/routes/admin_routes.py
from __future__ import annotations
import csv
import io
import json
import logging
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, make_response, url_for, current_app
from flask_login import login_required, current_user

from sqlalchemy import text, func, literal
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.exc import IntegrityError

from app.extensions import db, csrf, limiter
from app.utils.decorators import admin_required

from app.models.user import User
from app.models.encrypted_file import EncryptedFile
from app.models.file_share import FileShare
from app.models.credit_usage import CreditUsage
from app.models.purchase import Purchase
from app.models.billing_event import BillingEvent

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admin_logger() -> logging.Logger:
    name = current_app.config.get("ADMIN_ACTION_LOGGER_NAME")
    if name:
        return logging.getLogger(name)
    return current_app.logger


# -----------------------
# Helpers
# -----------------------
def _user_is_admin(u: User) -> bool:
    if hasattr(u, "is_admin"):
        attr = getattr(u, "is_admin")
        try:
            return bool(attr()) if callable(attr) else bool(attr)
        except Exception:
            pass
    if hasattr(u, "role"):
        try:
            return str(getattr(u, "role") or "").lower() == "admin"
        except Exception:
            pass
    return False


def _other_admins_exist(exclude_user_id: int) -> bool:
    for u in User.query.all():
        if u.id != exclude_user_id and _user_is_admin(u):
            return True
    return False


def _set_admin(u: User, value: bool) -> None:
    if hasattr(u, "role"):
        try:
            setattr(u, "role", "admin" if value else "user")
        except Exception:
            pass


def _set_hx_trigger(resp, payload: dict) -> None:
    safe = json.dumps(payload, separators=(",", ":")).replace("\r", "").replace("\n", "")
    resp.headers["HX-Trigger"] = safe


def _toast(message: str, variant: str = "success"):
    return {"toast": {"message": message, "variant": variant}}


def _render_row(u: User, msg: str | None = "Action effectuée."):
    u_is_admin = _user_is_admin(u)
    html = render_template("partials/admin_user_row.html", u=u, u_is_admin=u_is_admin)
    resp = make_response(html, 200)
    if msg:
        _set_hx_trigger(resp, _toast(msg, "success"))
    return resp


def _delete_download_tokens_for_user(user_id: int) -> None:
    # Compat: anciennes tables éventuelles
    try:
        db.session.execute(text("DELETE FROM download_token WHERE user_id = :uid"), {"uid": user_id})
        db.session.flush()
    except Exception:
        pass
    try:
        db.session.execute(text("DELETE FROM download_tokens WHERE user_id = :uid"), {"uid": user_id})
        db.session.flush()
    except Exception:
        pass


def _delete_download_tokens_for_file_ids(file_ids: list[int]) -> None:
    if not file_ids:
        return
    # Supprimer tous les tokens qui pointent vers ces fichiers (quel que soit l'user ayant généré le token)
    try:
        db.session.execute(text("DELETE FROM download_token WHERE file_id = ANY(:fids)"), {"fids": file_ids})
        db.session.flush()
    except Exception:
        pass
    try:
        db.session.execute(text("DELETE FROM download_tokens WHERE file_id = ANY(:fids)"), {"fids": file_ids})
        db.session.flush()
    except Exception:
        pass


def _col(model, names, default=None):
    for n in names:
        v = getattr(model, n, None)
        if isinstance(v, InstrumentedAttribute):
            return v
    return default


# -----------------------
# Dashboard
# -----------------------
@admin_bp.route("/panel")
@login_required
@admin_required
def dashboard():
    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin_panel.html", users=users)


# -----------------------
# Audit – helpers
# -----------------------
def _parse_dt(s: str):
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def _collect_audit_rows(q: str, kind: str, dt_from, dt_to):
    rows = []

    # BillingEvent
    if kind in ("all", "billing"):
        try:
            bq = db.session.query(
                BillingEvent.id.label("id"),
                BillingEvent.user_id.label("user_id"),
                BillingEvent.kind.label("kind"),
                func.coalesce(BillingEvent.credits_delta, -BillingEvent.credits_cost).label("amount"),
                BillingEvent.meta_json.label("meta"),
                BillingEvent.created_at.label("created_at"),
                User.username.label("username"),
                User.email.label("email"),
                literal("billing").label("source"),
            ).join(User, User.id == BillingEvent.user_id)
            if dt_from:
                bq = bq.filter(BillingEvent.created_at >= dt_from)
            if dt_to:
                bq = bq.filter(BillingEvent.created_at < dt_to)
            if q:
                like = f"%{q}%"
                bq = bq.filter(
                    func.lower(User.email).like(func.lower(like))
                    | func.lower(User.username).like(func.lower(like))
                )
            rows.extend(bq.all())
        except Exception:
            current_app.logger.exception("AUDIT/BILLING: échec de la requête")

    # CreditUsage
    if kind in ("all", "usage"):
        try:
            uq = db.session.query(
                CreditUsage.id.label("id"),
                CreditUsage.user_id.label("user_id"),
                CreditUsage.kind.label("kind"),
                CreditUsage.credits_cost.label("amount"),
                CreditUsage.meta_json.label("meta"),
                CreditUsage.created_at.label("created_at"),
                User.username.label("username"),
                User.email.label("email"),
                literal("usage").label("source"),
            ).join(User, User.id == CreditUsage.user_id)
            if dt_from:
                uq = uq.filter(CreditUsage.created_at >= dt_from)
            if dt_to:
                uq = uq.filter(CreditUsage.created_at < dt_to)
            if q:
                like = f"%{q}%"
                uq = uq.filter(
                    func.lower(User.email).like(func.lower(like))
                    | func.lower(User.username).like(func.lower(like))
                )
            rows.extend(uq.all())
        except Exception:
            current_app.logger.exception("AUDIT/USAGE: échec de la requête")

    # Purchase
    if kind in ("all", "purchase"):
        try:
            amount_col = _col(
                Purchase,
                ["credits_purchased", "credits, credits_delta", "quantity", "amount_credits"],
                literal(0),
            )
            meta_col = _col(Purchase, ["meta_json", "meta"], literal(None))
            created_col = _col(Purchase, ["created_at", "timestamp"], literal(None))
            kind_col = _col(Purchase, ["kind"], literal("purchase"))

            pq = db.session.query(
                Purchase.id.label("id"),
                Purchase.user_id.label("user_id"),
                kind_col.label("kind"),
                amount_col.label("amount"),
                meta_col.label("meta"),
                created_col.label("created_at"),
                User.username.label("username"),
                User.email.label("email"),
                literal("purchase").label("source"),
            ).join(User, User.id == Purchase.user_id)

            if isinstance(created_col, InstrumentedAttribute):
                if dt_from:
                    pq = pq.filter(created_col >= dt_from)
                if dt_to:
                    pq = pq.filter(created_col < dt_to)

            if q:
                like = f"%{q}%"
                pq = pq.filter(
                    func.lower(User.email).like(func.lower(like))
                    | func.lower(User.username).like(func.lower(like))
                )
            rows.extend(pq.all())
        except Exception:
            current_app.logger.exception("AUDIT/PURCHASE: échec de la requête")

    try:
        rows.sort(key=lambda r: r.created_at or datetime.min, reverse=True)
    except Exception:
        current_app.logger.exception("AUDIT: échec du tri")
    return rows


# -----------------------
# Audit – vue HTML
# -----------------------
@admin_bp.route("/audit")
@login_required
@admin_required
def audit():
    try:
        q = (request.args.get("q") or "").strip().lower()
        kind = (request.args.get("kind") or "all").lower()

        date_from = (request.args.get("date_from") or request.args.get("from") or "").strip()
        date_to = (request.args.get("date_to") or request.args.get("to") or "").strip()

        page = max(int(request.args.get("page", 1) or 1), 1)
        per_page = min(max(int(request.args.get("per_page", 20) or 20), 5), 100)

        dt_from = _parse_dt(date_from)
        dt_to = _parse_dt(date_to)
        if dt_to:
            dt_to = dt_to + timedelta(days=1)

        rows = _collect_audit_rows(q, kind, dt_from, dt_to)
        total = len(rows)
        start = (page - 1) * per_page
        end = start + per_page
        page_rows = rows[start:end]
        total_pages = (total + per_page - 1) // per_page or 1

        return render_template(
            "admin_audit.html",
            rows=page_rows,
            page=page,
            total_pages=total_pages,
            total=total,
            q=q,
            kind=kind,
            date_from=date_from,
            date_to=date_to,
            per_page=per_page,
        )
    except Exception:
        current_app.logger.exception("AUDIT/VIEW: erreur imprévue")
        return render_template(
            "admin_audit.html",
            rows=[],
            page=1,
            total_pages=1,
            total=0,
            q="",
            kind="all",
            date_from="",
            date_to="",
            per_page=20,
        ), 200


# -----------------------
# Audit – export CSV
# -----------------------
@admin_bp.route("/audit.csv")
@login_required
@admin_required
def audit_csv():
    q = (request.args.get("q") or "").strip().lower()
    kind = (request.args.get("kind") or "all").lower()

    date_from = (request.args.get("date_from") or request.args.get("from") or "").strip()
    date_to = (request.args.get("date_to") or request.args.get("to") or "").strip()

    dt_from = _parse_dt(date_from)
    dt_to = _parse_dt(date_to)
    if dt_to:
        dt_to = dt_to + timedelta(days=1)

    rows = _collect_audit_rows(q, kind, dt_from, dt_to)

    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(["created_at", "source", "user_id", "username", "email", "kind", "amount", "meta"])
    for r in rows:
        w.writerow(
            [
                r.created_at or "",
                r.source,
                r.user_id,
                (r.username or ""),
                (r.email or ""),
                (r.kind or ""),
                r.amount,
                (r.meta or ""),
            ]
        )

    resp = make_response(buf.getvalue().encode("utf-8"))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=audit.csv"
    return resp


# -----------------------
# Création utilisateur (HTMX)
# -----------------------
@admin_bp.route("/users", methods=["POST"])
@login_required
@admin_required
@limiter.limit("60/hour")
@csrf.exempt
def create_user():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    is_admin_form = request.form.get("is_admin") in ("on", "true", "1", "yes")

    if not username or not email or not password:
        resp = make_response("", 400)
        _set_hx_trigger(resp, _toast("Champs requis.", "danger"))
        return resp

    if User.query.filter_by(email=email).first():
        resp = make_response("", 409)
        _set_hx_trigger(resp, _toast("Email déjà utilisé.", "danger"))
        return resp

    u = User(username=username, email=email)
    if hasattr(u, "set_password") and callable(u.set_password):
        u.set_password(password)
    else:
        setattr(u, "password", password)

    _set_admin(u, is_admin_form)
    db.session.add(u)
    db.session.commit()

    _admin_logger().info(
        json.dumps({"action": "create_user", "by": current_user.id, "user_id": u.id, "email": u.email})
    )
    return _render_row(u, "Utilisateur créé.")


# -----------------------
# Promouvoir / Rétrograder / Supprimer
# -----------------------
@admin_bp.route("/users/<int:user_id>/promote", methods=["POST"])
@login_required
@admin_required
@limiter.limit("60/hour")
@csrf.exempt
def promote_user(user_id: int):
    u = User.query.get_or_404(user_id)
    _set_admin(u, True)
    db.session.commit()
    _admin_logger().info(json.dumps({"action": "promote", "by": current_user.id, "user_id": u.id}))
    return _render_row(u, "Utilisateur promu admin.")


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
@limiter.limit("60/hour")
@csrf.exempt
def delete_user(user_id: int):
    log = _admin_logger()
    log.info(f"[ADMIN] delete_user start user_id={user_id} by={current_user.id}")

    u = User.query.get_or_404(user_id)

    # Garde-fous
    if current_user.id == u.id:
        resp = make_response("", 400)
        _set_hx_trigger(resp, _toast("Vous ne pouvez pas vous supprimer vous-même.", "danger"))
        return resp

    if _user_is_admin(u) and not _other_admins_exist(u.id):
        resp = make_response("", 400)
        _set_hx_trigger(resp, _toast("Impossible : ce serait le dernier administrateur.", "danger"))
        return resp

    try:
        # 1) Retirer les partages (propriétaire + reçu)
        FileShare.query.filter_by(owner_id=u.id).delete(synchronize_session=False)
        FileShare.query.filter_by(shared_with_user_id=u.id).delete(synchronize_session=False)
        db.session.flush()

        # 2) Supprimer les DownloadToken liés au user (tables héritées possibles)
        try:
            db.session.execute(text("DELETE FROM download_token WHERE user_id = :uid"), {"uid": u.id})
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[ADMIN] download_token by user_id skip: {e}")

        try:
            db.session.execute(text("DELETE FROM download_tokens WHERE user_id = :uid"), {"uid": u.id})
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[ADMIN] download_tokens by user_id skip: {e}")

        # 3) Récupérer les fichiers de l’utilisateur
        file_ids = [fid for (fid,) in db.session.query(EncryptedFile.id).filter_by(user_id=u.id).all()]

        # 4) Supprimer les DownloadToken par file_id (boucle => évite IN/ANY)
        if file_ids:
            for fid in file_ids:
                try:
                    db.session.execute(text("DELETE FROM download_token  WHERE file_id = :fid"), {"fid": fid})
                    db.session.flush()
                except Exception:
                    db.session.rollback()
                try:
                    db.session.execute(text("DELETE FROM download_tokens WHERE file_id = :fid"), {"fid": fid})
                    db.session.flush()
                except Exception:
                    db.session.rollback()

        # 5) Logs de crédits/achats (silencieux si tables absentes)
        try:
            CreditUsage.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[ADMIN] credit_usage skip: {e}")

        try:
            Purchase.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[ADMIN] purchase skip: {e}")

        try:
            BillingEvent.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[ADMIN] billing_event skip: {e}")

        # 6) Supprimer les fichiers chiffrés
        for f in EncryptedFile.query.filter_by(user_id=u.id).all():
            db.session.delete(f)
        db.session.flush()

        # 7) Supprimer l’utilisateur
        db.session.delete(u)
        db.session.commit()

        log.info(json.dumps({"action": "delete_user", "by": current_user.id, "user_id": user_id}))
        resp = make_response("", 204)
        _set_hx_trigger(resp, _toast("Utilisateur supprimé.", "success"))
        return resp

    except IntegrityError as e:
        # Soft-delete de secours si contrainte FK
        db.session.rollback()
        try:
            if hasattr(u, "is_active"):
                setattr(u, "is_active", False)
            if hasattr(u, "role"):
                setattr(u, "role", "deleted")
            suffix = f".deleted.{u.id}.{int(time.time())}"
            if getattr(u, "email", None):
                u.email = f"{secrets.token_hex(8)}{suffix}@example.invalid"
            if getattr(u, "username", None):
                u.username = f"user_{u.id}{suffix}"
            db.session.commit()
            log.info(json.dumps({"action": "soft_delete_user", "by": current_user.id, "user_id": user_id}))
            resp = make_response("", 204)
            _set_hx_trigger(resp, _toast("Utilisateur anonymisé (soft delete).", "info"))
            return resp
        except Exception as e2:
            db.session.rollback()
            log.exception(f"[ADMIN] soft delete failed user_id={user_id}: {e2}")
            resp = make_response("", 500)
            _set_hx_trigger(resp, _toast("Erreur serveur pendant la suppression.", "danger"))
            return resp
    except Exception as e:
        db.session.rollback()
        log.exception(f"[ADMIN] delete_user unexpected error user_id={user_id}: {e}")
        resp = make_response("", 500)
        _set_hx_trigger(resp, _toast("Erreur serveur pendant la suppression.", "danger"))
        return resp