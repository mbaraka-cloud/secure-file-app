# app/routes/main_routes.py
import os
import mimetypes
import logging
import hashlib
import math
from io import BytesIO

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, send_file, jsonify, current_app, render_template_string, session, make_response
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import magic
from sqlalchemy import func, desc
import json  # ← utilisé pour HX-Trigger
from werkzeug.security import check_password_hash
from app.utils.user_delete import delete_user_cascade
from app.utils.audit_log import log_account_deletion

from app.utils.encryption_utils import encrypt_file_hybrid, decrypt_file_hybrid
from app.utils.urls import sign_download_token, verify_download_token
from app.utils.mime_category import categorize_mime
from app.models.user import User
from app.models.encrypted_file import EncryptedFile
from app.models.download_token import DownloadToken
from app.models.file_share import FileShare
from app.models.billing_event import BillingEvent
from app.extensions import db, limiter
from app.forms.upload_form import UploadForm
from app.forms.share_form import ShareForm, UnshareForm

# (7) utilitaire ZIP (stream/sans exploser la RAM)
from app.utils.zip_utils import build_zip_file

main_bp = Blueprint("main", __name__)

# Logger admin → admin_actions.log
admin_logger = logging.getLogger("admin_logger")
admin_logger.setLevel(logging.INFO)

def _ensure_logger():
    if admin_logger.handlers:
        return
    log_dir = current_app.config.get("LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "logs"))
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, "admin_actions.log")
    handler = logging.FileHandler(log_file_path)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    admin_logger.addHandler(handler)

def _user_storage_usage(user_id: int):
    count = db.session.query(func.count(EncryptedFile.id)).filter_by(user_id=user_id).scalar() or 0
    total_bytes = db.session.query(
        func.coalesce(func.sum(func.length(EncryptedFile.ciphertext)), 0)
    ).filter(EncryptedFile.user_id == user_id).scalar() or 0
    return int(count), int(total_bytes)

def _has_access(enc_file: EncryptedFile, user: User) -> bool:
    if user.is_admin() or enc_file.user_id == user.id:
        return True
    return db.session.query(FileShare.id).filter_by(file_id=enc_file.id, shared_with_user_id=user.id).first() is not None

def _order_col():
    return getattr(EncryptedFile, "uploaded_at", getattr(EncryptedFile, "created_at", EncryptedFile.id))

def _wants_json() -> bool:
    if request.headers.get("HX-Request"):
        return False
    accept = request.headers.get("Accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return True
    if request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest":
        return True
    return False

def _apply_sort(query, sort, direction):
    direction = (direction or "desc").lower()
    col = EncryptedFile.filename if (sort or "date") == "name" else _order_col()
    col = col.asc() if direction == "asc" else col.desc()
    return query.order_by(col)

def _received_files_query(user_id: int):
    size_expr = func.length(EncryptedFile.ciphertext).label("size_bytes")
    created_col = getattr(EncryptedFile, "uploaded_at",
                  getattr(EncryptedFile, "created_at", EncryptedFile.id)).label("file_created_at")

    q = (
        db.session.query(
            FileShare.id.label("share_id"),
            EncryptedFile.id.label("file_id"),
            EncryptedFile.filename.label("filename"),
            size_expr,
            created_col,
            User.username.label("owner_name"),
        )
        .join(EncryptedFile, EncryptedFile.id == FileShare.file_id)
        .join(User, User.id == EncryptedFile.user_id)
        .filter(FileShare.shared_with_user_id == user_id)
        .order_by(desc(FileShare.id))
    )
    return q

@main_bp.route("/")
@login_required
def index():
    _ensure_logger()
    order_by_col = _order_col().desc()

    shared_with_me = (
        db.session.query(EncryptedFile)
        .join(FileShare, FileShare.file_id == EncryptedFile.id)
        .filter(FileShare.shared_with_user_id == current_user.id)
        .order_by(order_by_col)
        .all()
    )

    raw_counts = (
        db.session.query(EncryptedFile.category, func.count(EncryptedFile.id))
        .filter(EncryptedFile.user_id == current_user.id)
        .group_by(EncryptedFile.category)
        .all()
    )
    counts = {c: n for c, n in raw_counts}
    total = sum(counts.values())

    categories = ["Tous", "Document", "Image", "Audio", "Vidéo", "Logiciel", "Archive", "Autre"]
    cats_with_counts = [(cat, total if cat == "Tous" else counts.get(cat, 0)) for cat in categories]

    received_q = _received_files_query(current_user.id)
    received_total = received_q.count()
    recent_received = received_q.limit(5).all()

    return render_template(
        "home.html",
        shared_with_me=shared_with_me,
        cats_with_counts=cats_with_counts,
        received_total=received_total,
        recent_received=recent_received,
    )

@main_bp.route("/received/box")
@login_required
def received_box():
    received_q = _received_files_query(current_user.id)
    received_total = received_q.count()
    recent_received = received_q.limit(5).all()
    return render_template(
        "partials/received_files_box.html",
        received_total=received_total,
        recent_received=recent_received,
    )

@main_bp.route("/usage")
@login_required
def usage():
    count, total_bytes = _user_storage_usage(current_user.id)
    max_files = int(current_app.config.get("MAX_FILES_PER_USER", 100))
    max_bytes = int(current_app.config.get("MAX_TOTAL_BYTES_PER_USER", 512 * 1024 * 1024))
    return jsonify({
        "count": count,
        "max_files": max_files,
        "total_bytes": total_bytes,
        "max_bytes": max_bytes
    })

@main_bp.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per hour")
def upload_file():
    _ensure_logger()
    form = UploadForm()
    if request.method == "POST":
        max_files = int(current_app.config.get("MAX_FILES_PER_USER", 100))
        max_bytes = int(current_app.config.get("MAX_TOTAL_BYTES_PER_USER", 512 * 1024 * 1024))
        cur_count, cur_bytes = _user_storage_usage(current_user.id)

        def _resp(success: bool, msg: str, code: int = 200):
            if _wants_json():
                return jsonify({"status": "success" if success else "error", "message": msg}), code
            flash(msg, "success" if success else "danger")
            return redirect(url_for("main.upload_file"))

        if cur_count >= max_files:
            return _resp(False, "Quota atteint : nombre maximum de fichiers 🚫", 403)

        if "file" not in request.files or request.files["file"].filename == "":
            return _resp(False, "Aucun fichier sélectionné ou nom invalide ❌", 400)

        file = request.files["file"]
        filename = secure_filename(file.filename)

        allowed = current_app.config.get("ALLOWED_EXTENSIONS", set())
        if "." not in filename:
            return _resp(False, "Nom de fichier invalide ❌", 400)
        ext = filename.rsplit(".", 1)[-1].lower()
        if allowed and ext not in allowed:
            return _resp(False, f"Extension .{ext} non autorisée ❌", 400)

        head = file.read(2048); file.seek(0)
        try:
            mime_magic = magic.from_buffer(head, mime=True)
        except Exception:
            mime_magic = None

        file_data = file.read()
        if cur_bytes + len(file_data) > max_bytes:
            return _resp(False, "Quota atteint : taille totale dépassée 🚫", 403)

        try:
            result = encrypt_file_hybrid(file_data)
            content_type = mime_magic or file.mimetype or "application/octet-stream"
            category = categorize_mime(content_type, filename)

            new_file = EncryptedFile(
                filename=filename,
                content_type=content_type,
                ciphertext=result["ciphertext"],
                nonce=result["nonce"],
                tag=result["tag"],
                encrypted_key=result["encrypted_key"],
                user_id=current_user.id,
                category=category,
            )
            db.session.add(new_file)
            db.session.commit()

            admin_logger.info(f"{current_user.username} a uploadé {filename}")
            return _resp(True, "Fichier chiffré et uploadé avec succès ✅", 200)
        except Exception as e:
            db.session.rollback()
            return _resp(False, f"Erreur lors de l'upload : {str(e)}", 500)

    return render_template("upload.html", form=form)

# ---------------------------
# Partage 1 fichier (existant) — support HTMX inline
# ---------------------------
@main_bp.route("/share/<int:file_id>", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def share_file(file_id):
    _ensure_logger()
    form = ShareForm()
    if not form.validate_on_submit():
        if request.headers.get("HX-Request"):
            resp = make_response('<div class="text-sm text-red-700">Requête invalide (CSRF / champs) ❌</div>')
            resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": "Requête invalide ❌", "variant": "danger"}})
            return resp
        flash("Requête invalide (CSRF / champs) ❌", "danger")
        return redirect(url_for("main.index"))

    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not current_user.is_admin() and enc_file.user_id != current_user.id:
        if request.headers.get("HX-Request"):
            resp = make_response('<div class="text-sm text-red-700">Accès non autorisé ❌</div>')
            resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": "Accès non autorisé ❌", "variant": "danger"}})
            return resp
        flash("Accès non autorisé au partage ❌", "danger")
        return redirect(url_for("main.index"))

    email = form.email.data.strip().lower()
    target = User.query.filter_by(email=email).first()
    if not target:
        if request.headers.get("HX-Request"):
            resp = make_response('<div class="text-sm text-red-700">Utilisateur introuvable pour cet email ❌</div>')
            resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": "Utilisateur introuvable ❌", "variant": "danger"}})
            return resp
        flash("Utilisateur introuvable pour cet email ❌", "danger")
        return redirect(url_for("main.index"))

    if target.id == enc_file.user_id:
        if request.headers.get("HX-Request"):
            resp = make_response('<div class="text-sm text-gray-700">Inutile de partager avec le propriétaire 😉</div>')
            resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": "Déjà propriétaire 😉", "variant": "info"}})
            return resp
        flash("Inutile de partager avec le propriétaire 😉", "info")
        return redirect(url_for("main.index"))

    exists = db.session.query(FileShare.id).filter_by(file_id=enc_file.id, shared_with_user_id=target.id).first()
    if exists:
        if request.headers.get("HX-Request"):
            resp = make_response('<div class="text-sm text-gray-700">Déjà partagé avec cet utilisateur.</div>')
            resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": "Déjà partagé.", "variant": "info"}})
            return resp
        flash("Déjà partagé avec cet utilisateur.", "info")
        return redirect(url_for("main.index"))

    share = FileShare(file_id=enc_file.id, owner_id=enc_file.user_id, shared_with_user_id=target.id)
    db.session.add(share)
    db.session.commit()

    admin_logger.info(f"{current_user.username} a partagé {enc_file.filename} avec {email}")

    if request.headers.get("HX-Request"):
        # Remplace le bloc inline par une confirmation
        html = f'<div class="text-sm text-green-700">Partagé avec {email} ✅</div>'
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"toast": {"message": f"Partagé avec {email} ✅", "variant": "success"}})
        return resp

    flash(f"Partagé avec {email} ✅", "success")
    return redirect(url_for("main.index"))

# ---------------------------
# Partage EN MASSE
# ---------------------------
@main_bp.route("/share/bulk", methods=["GET", "POST"])
@login_required
def share_bulk():
    _ensure_logger()
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        file_ids = request.form.getlist("file_ids")
        if not email:
            flash("Email requis ❌", "danger")
            return redirect(url_for("main.share_bulk"))
        if not file_ids:
            flash("Sélectionnez au moins un fichier à partager ❌", "danger")
            return redirect(url_for("main.share_bulk"))

        target = User.query.filter_by(email=email).first()
        if not target:
            flash("Utilisateur introuvable pour cet email ❌", "danger")
            return redirect(url_for("main.share_bulk"))

        created = 0
        for fid in file_ids:
            try:
                fid_int = int(fid)
            except ValueError:
                continue
            enc_file = EncryptedFile.query.get(fid_int)
            if not enc_file or enc_file.user_id != current_user.id:
                continue
            if target.id == enc_file.user_id:
                continue
            exists = db.session.query(FileShare.id).filter_by(file_id=enc_file.id, shared_with_user_id=target.id).first()
            if exists:
                continue
            db.session.add(FileShare(file_id=enc_file.id, owner_id=current_user.id, shared_with_user_id=target.id))
            created += 1

        if created > 0:
            db.session.commit()
            flash(f"{created} fichier(s) partagé(s) avec {email} ✅", "success")
            admin_logger.info(f"{current_user.username} a partagé {created} fichier(s) avec {email} (bulk)")
        else:
            flash("Aucun partage créé (doublons/propriété) ℹ️", "info")
        return redirect(url_for("main.share_bulk"))

    # GET
    raw_counts = (
        db.session.query(EncryptedFile.category, func.count(EncryptedFile.id))
        .filter(EncryptedFile.user_id == current_user.id)
        .group_by(EncryptedFile.category)
        .all()
    )
    counts = {c: n for c, n in raw_counts}
    total = sum(counts.values())
    categories = ["Tous", "Document", "Image", "Audio", "Vidéo", "Logiciel", "Archive", "Autre"]
    cats_with_counts = [(cat, total if cat == "Tous" else counts.get(cat, 0)) for cat in categories]

    return render_template("share_bulk.html", cats_with_counts=cats_with_counts)

@main_bp.get("/share/bulk/files")
@login_required
def share_bulk_files():
    """Liste filtrable/paginée de MES fichiers (pour la page de partage en masse)."""
    category = request.args.get("category", "Tous")
    q = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "date")     # "date" | "name"
    direction = request.args.get("dir", "desc") # "asc" | "desc"
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = int(request.args.get("per_page", 10) or 10)

    query = EncryptedFile.query.filter_by(user_id=current_user.id)
    if category and category != "Tous":
        query = query.filter(EncryptedFile.category == category)
    if q:
        like = f"%{q}%"
        query = query.filter(EncryptedFile.filename.ilike(like))

    total = query.count()
    total_pages = max(math.ceil(total / per_page), 1)

    query = _apply_sort(query, sort, direction)
    files = query.limit(per_page).offset((page - 1) * per_page).all()

    return render_template(
        "partials/share_file_list.html",
        files=files,
        page=page,
        total_pages=total_pages,
        sort=sort,
        direction=direction,
        q=q,
        category=category,
        per_page=per_page,
    )

# ============================================================
#            ⬇️ AJOUTS POUR (3) ET (4) DÉJÀ EN PLACE ⬇️
# ============================================================

@main_bp.get("/me/credits/fragment")
@login_required
def me_credits_fragment():
    return render_template("partials/credits_badge.html", credits=int(current_user.credits or 0))

from datetime import datetime
import zipfile
import time

def _sum_bytes(files):
    total = 0
    for f in files:
        total += len(getattr(f, "ciphertext", b"") or b"")
    return int(total)

def _parse_ids_arg():
    ids_set = set()

    ids_csv = (request.args.get("ids") or request.form.get("ids") or "").strip()
    if ids_csv:
        tmp = ids_csv.replace(";", ",").replace("\n", ",").replace("\r", ",").replace("\t", " ")
        for part in [p for p in tmp.replace(" ", ",").split(",") if p]:
            try:
                v = int(part)
                if v > 0:
                    ids_set.add(v)
            except Exception:
                pass

    for key in ("ids", "ids[]", "file_ids", "file_ids[]"):
        for raw in request.args.getlist(key) + request.form.getlist(key):
            try:
                v = int(raw)
                if v > 0:
                    ids_set.add(v)
            except Exception:
                pass

    return list(ids_set)

def _calc_credits_cost(total_bytes: int) -> int:
    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))
    if total_bytes <= 0:
        return 0
    total_mo = total_bytes / float(1024 * 1024)
    return int(session_fee + math.floor(total_mo / max(palier_mo, 1)))

def _log_billing_event(label: str, file_ids: list[int], total_bytes: int, credits: int):
    try:
        ev = BillingEvent(
            user_id=current_user.id,
            kind="download",
            label=label,
            file_ids_json=json.dumps(sorted(file_ids)),
            bytes_total=int(total_bytes),
            credits_cost=int(credits),
            meta_json=None,
        )
        db.session.add(ev)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("[billing] failed to log BillingEvent")

def _charge_option_a_or_redirect(total_bytes: int, label: str, file_ids: list[int]):
    needed = _calc_credits_cost(total_bytes)
    have = int(current_user.credits or 0)

    sig_src = f"{current_user.id}|{label}|{','.join(map(str, sorted(file_ids)))}|{int(total_bytes)}"
    sig = hashlib.sha256(sig_src.encode("utf-8")).hexdigest()
    last_sig = session.get("last_charge_sig")
    last_ts = float(session.get("last_charge_ts") or 0)
    now = time.time()
    window_sec = int(current_app.config.get("BILLING_DEBIT_IDEMPOTENCY_WINDOW_SEC", 20))

    if last_sig == sig and (now - last_ts) <= window_sec:
        admin_logger.info(f"Idempotence: lot déjà débité récemment, pas de redébit (sig={sig[:8]}…)")
        return True

    if needed <= 0:
        return True

    if have < needed:
        admin_logger.info(
            f"{current_user.username} tentative DL lot '{label}' REFUSEE: crédits insuffisants "
            f"(needed={needed}, have={have})"
        )
        if _wants_json():
            return jsonify({"ok": False, "reason": "insufficient_credits", "needed": needed, "have": have}), 402
        flash(f"Crédits insuffisants (coût du lot = {needed} crédits).", "danger")
        return redirect(url_for("stripe.buy_page"))

    current_user.credits = have - needed
    db.session.commit()
    session["last_charge_sig"] = sig
    session["last_charge_ts"] = now

    _log_billing_event(label=label, file_ids=file_ids, total_bytes=total_bytes, credits=needed)

    admin_logger.info(
        f"{current_user.username} debit {needed} crédits (Option A) label={label} files={file_ids} total_bytes={total_bytes}"
    )
    return True

def _filter_accessible(files):
    return [f for f in files if _has_access(f, current_user)]

# ---------------------------
# (4) CONFIRMATION AVANT TÉLÉCHARGEMENT (mes fichiers & partagés)
# ---------------------------
@main_bp.get("/files/<int:file_id>/confirm-download")
@login_required
def confirm_download_modal(file_id: int):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Accès non autorisé ❌","danger");</script>'
        )

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    needed = _calc_credits_cost(total_bytes)

    return render_template(
        "modals/confirm_download.html",
        file=enc_file,
        needed_credits=needed,
        total_bytes=total_bytes
    )

@main_bp.post("/files/<int:file_id>/confirm-download")
@login_required
def perform_download_after_confirm(file_id: int):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Accès non autorisé ❌","danger");</script>'
        )

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    charge_result = _charge_option_a_or_redirect(
        total_bytes=total_bytes,
        label="my_one_confirm",
        file_ids=[enc_file.id]
    )
    if charge_result is not True:
        return charge_result

    token = sign_download_token(file_id=enc_file.id, user_id=current_user.id)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    exists = db.session.query(DownloadToken.id).filter_by(token_hash=token_hash).first()
    if not exists:
        db.session.add(DownloadToken(token_hash=token_hash, file_id=enc_file.id, user_id=current_user.id))
        db.session.commit()

    # Mise à jour du badge crédits en OOB + redirection HTMX (CSP-safe)
        # ... après avoir généré `token` et mis à jour les crédits ...
    dl_url = url_for("main.download_with_token", token=token)

    # Fragment "crédits" à jour (OOB)
    credits_html = render_template("partials/credits_badge.html", credits=int(current_user.credits or 0))

    # Réponse HTMX : on vide la modale, on injecte un iFrame invisible pour déclencher le download,
    # et on déclenche un refresh auto (voir listener "page:refresh" dans base.html).
    resp_html = (
        f'{credits_html}'
        f'<div id="modal-root" hx-swap-oob="true"></div>'
        f'<div id="download-iframe" hx-swap-oob="true">'
        f'  <iframe src="{dl_url}" style="display:none"></iframe>'
        f'</div>'
    )

    resp = make_response(resp_html, 200)
    # ferme la modale + demande de refresh auto
    resp.headers["HX-Trigger"] = json.dumps({"modal:close": True, "page:refresh": True})
    # aucun swap sur la modale elle-même (c’est OOB)
    return resp



    return redirect(url_for("main.download_with_token", token=token))

@main_bp.post("/modal/close-refresh")
@login_required
def modal_close_refresh():
    # Vide la modale en OOB et déclenche un refresh auto
    resp = make_response('<div id="modal-root" hx-swap-oob="true"></div>', 200)
    resp.headers["HX-Trigger"] = json.dumps({"modal:close": True, "page:refresh": True})
    return resp


# ===== Confirmation & téléchargement pour FICHIERS PARTAGÉS =====

@main_bp.get("/shared/<int:file_id>/confirm-download")
@login_required
def shared_confirm_download_modal(file_id: int):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        return render_template_string(
            '<div id="modal-root"></div><script>try{window.showToast("Accès non autorisé ❌","danger");}catch(_){}</script>'
        )

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    needed = _calc_credits_cost(total_bytes)
    return render_template(
        "modals/confirm_download.html",
        file=enc_file,
        needed_credits=needed,
        total_bytes=total_bytes
    )

@main_bp.post("/shared/<int:file_id>/confirm-download")
@login_required
def shared_perform_download_after_confirm(file_id: int):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        return render_template_string('<div id="modal-root"></div>')

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    charge_result = _charge_option_a_or_redirect(
        total_bytes=total_bytes,
        label="shared_one_confirm",
        file_ids=[enc_file.id]
    )
    if charge_result is not True:
        return charge_result

    # Lien signé one-time
    token = sign_download_token(file_id=enc_file.id, user_id=current_user.id)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    exists = db.session.query(DownloadToken.id).filter_by(token_hash=token_hash).first()
    if not exists:
        db.session.add(DownloadToken(token_hash=token_hash, file_id=enc_file.id, user_id=current_user.id))
        db.session.commit()

        html = render_template("partials/credits_badge.html", credits=int(current_user.credits or 0))
        if request.headers.get("HX-Request"):
            resp = make_response(
                f'{html}'
                f'<div id="modal-root" hx-swap-oob="true"></div>'
            )
            resp.headers['HX-Trigger'] = json.dumps({"modal:close": True})
            resp.headers['HX-Redirect'] = url_for("main.download_with_token", token=token)
            resp.status_code = 204
            return resp



    return redirect(url_for("main.download_with_token", token=token))

# ---------------------------
# Download / Delete (MES fichiers)
# ---------------------------
@main_bp.route("/download/<int:file_id>")
@login_required
@limiter.limit("60 per hour")
def download_file(file_id):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        flash("Accès non autorisé à ce fichier ❌", "danger")
        return redirect(url_for("main.index"))

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    charge_result = _charge_option_a_or_redirect(
        total_bytes,
        label="my_one",
        file_ids=[enc_file.id]
    )
    if charge_result is not True:
        return charge_result

    token = sign_download_token(file_id=enc_file.id, user_id=current_user.id)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    exists = db.session.query(DownloadToken.id).filter_by(token_hash=token_hash).first()
    if not exists:
        db.session.add(DownloadToken(token_hash=token_hash, file_id=enc_file.id, user_id=current_user.id))
        db.session.commit()

    return redirect(url_for("main.download_with_token", token=token))

@main_bp.route("/dl/<token>")
@login_required
@limiter.limit("60 per hour")
def download_with_token(token):
    _ensure_logger()
    from datetime import datetime, timedelta
    try:
        data = verify_download_token(token)
        file_id = int(data["f"])
        token_user_id = int(data["u"])
    except Exception:
        flash("Lien de téléchargement invalide ou expiré ❌", "danger")
        return redirect(url_for("main.index"))

    if token_user_id != current_user.id and not current_user.is_admin():
        flash("Lien de téléchargement non autorisé ❌", "danger")
        return redirect(url_for("main.index"))

    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        flash("Accès non autorisé à ce fichier ❌", "danger")
        return redirect(url_for("main.index"))

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    rec = DownloadToken.query.filter_by(token_hash=token_hash).first()
    if not rec or rec.used_at is not None:
        flash("Lien de téléchargement déjà utilisé ou invalide ❌", "danger")
        return redirect(url_for("main.index"))

    ttl_minutes = int(current_app.config.get("DOWNLOAD_TOKEN_TTL_MINUTES", 30))
    if rec.is_expired(ttl_minutes):
        flash("Lien de téléchargement expiré ❌ — veuillez relancer le téléchargement.", "danger")
        return redirect(url_for("main.index"))

    try:
        plaintext = decrypt_file_hybrid(
            enc_file.ciphertext,
            enc_file.encrypted_key,
            enc_file.nonce,
            enc_file.tag
        )
        tmp_file = BytesIO(plaintext); tmp_file.seek(0)
        rec.used_at = func.now()
        db.session.commit()

        admin_logger.info(f"{current_user.username} a téléchargé {enc_file.filename} via lien signé (one-time)")
        mime_type = getattr(enc_file, "content_type", None) or mimetypes.guess_type(enc_file.filename)[0]
        return send_file(tmp_file, as_attachment=True, download_name=enc_file.filename, mimetype=mime_type or "application/octet-stream")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors du déchiffrement : {str(e)} ❌", "danger")
        return redirect(url_for("main.index"))

@main_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def delete_file(file_id):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not current_user.is_admin() and enc_file.user_id != current_user.id:
        flash("Accès non autorisé ❌", "danger")
        return redirect(url_for("main.index"))
    try:
        db.session.delete(enc_file)
        db.session.commit()
        admin_logger.info(f"{current_user.username} a supprimé {enc_file.filename}")
        flash("Fichier supprimé ✅", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la suppression : {str(e)} ❌", "danger")
    return redirect(url_for("main.index"))

# ---------------------------
# Filtrage “Mes fichiers” (accueil) — pagination + tri
# ---------------------------
@main_bp.get("/files/filter")
@login_required
def filter_files():
    category = request.args.get("category", "Tous")
    q = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "date")
    direction = request.args.get("dir", "desc")
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = int(request.args.get("per_page", 10) or 10)

    query = EncryptedFile.query.filter_by(user_id=current_user.id)
    if category and category != "Tous":
        query = query.filter(EncryptedFile.category == category)
    if q:
        like = f"%{q}%"
        query = query.filter(EncryptedFile.filename.ilike(like))

    total = query.count()
    total_pages = max(math.ceil(total / per_page), 1)

    query = _apply_sort(query, sort, direction)
    files = query.limit(per_page).offset((page - 1) * per_page).all()

    shares_map = {}
    if files:
        file_ids = [f.id for f in files]
        rows = (
            db.session.query(FileShare.file_id, User.id, User.email)
            .join(User, User.id == FileShare.shared_with_user_id)
            .filter(FileShare.file_id.in_(file_ids))
            .all()
        )
        for file_id, uid, email in rows:
            shares_map.setdefault(file_id, []).append({"user_id": uid, "email": email})

    return render_template_string(
    """
<div id="files-list">
  <div class="flex flex-wrap items-center gap-2 mb-3">
    <span class="text-sm text-gray-600">Trier par:</span>
    <button class="px-2 py-1 border rounded {{ 'bg-gray-200' if sort=='date' else 'bg-white' }}"
            hx-get="{{ url_for('main.filter_files') }}" hx-include="#search-form"
            hx-vals='{"sort":"date","dir":"{{ direction }}","page":1,"per_page":{{ per_page }}}'
            hx-target="#files-list" hx-swap="outerHTML">Date</button>
    <button class="px-2 py-1 border rounded {{ 'bg-gray-200' if sort=='name' else 'bg-white' }}"
            hx-get="{{ url_for('main.filter_files') }}" hx-include="#search-form"
            hx-vals='{"sort":"name","dir":"{{ direction }}","page":1,"per_page":{{ per_page }}}'
            hx-target="#files-list" hx-swap="outerHTML">Nom</button>
    <span class="ml-3 text-sm text-gray-600">Ordre:</span>
    <button class="px-2 py-1 border rounded {{ 'bg-gray-200' if direction=='asc' else 'bg-white' }}"
            hx-get="{{ url_for('main.filter_files') }}" hx-include="#search-form"
            hx-vals='{"sort":"{{ sort }}","dir":"asc","page":1,"per_page":{{ per_page }}}'
            hx-target="#files-list" hx-swap="outerHTML">Asc</button>
    <button class="px-2 py-1 border rounded {{ 'bg-gray-200' if direction=='desc' else 'bg-white' }}"
            hx-get="{{ url_for('main.filter_files') }}" hx-include="#search-form"
            hx-vals='{"sort":"{{ sort }}","dir":"desc","page":1,"per_page":{{ per_page }}}'
            hx-target="#files-list" hx-swap="outerHTML">Desc</button>
    <span class="ml-3 text-xs text-gray-500">Résultats: {{ (page-1)*per_page + 1 if files else 0 }}–{{ (page-1)*per_page + (files|length) }} / {{ total }}</span>
  </div>

  {% if files %}
    <!-- IMPORTANT : id + classes identiques à la page "Partagés", pour réutiliser static/js/shared.js -->
    <div class="bg-white rounded shadow divide-y" id="shared-list">
      {% for f in files %}
        <div class="p-3 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <!-- case à cocher prise en charge par shared.js -->
            <input type="checkbox"
                   class="row-check h-4 w-4"
                   name="ids"
                   value="{{ f.id }}"
                   data-bytes="{{ (f.ciphertext|length) or 0 }}">
            <div>
              <div class="font-medium">{{ f.filename }}</div>
              <div class="text-xs text-gray-500">
                ID: {{ f.id }} — Type: {{ f.content_type or 'inconnu' }} — Catégorie: {{ f.category }}
              </div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <!-- Télécharger via modal de confirmation -->
            <button
              class="px-3 py-1 rounded bg-green-600 text-white hover:bg-green-700"
              hx-get="{{ url_for('main.confirm_download_modal', file_id=f.id) }}"
              hx-target="#modal-root"
              hx-swap="innerHTML">
              Télécharger
            </button>

            <!-- Partage inline -->
            <button
              class="px-3 py-1 rounded bg-blue-600 text-white hover:bg-blue-700"
              hx-get="{{ url_for('main.share_inline_form', file_id=f.id) }}"
              hx-target="#share-box-{{ f.id }}"
              hx-swap="outerHTML">
              Partager
            </button>

            <form method="post" action="{{ url_for('main.delete_file', file_id=f.id) }}" data-confirm="Supprimer {{ f.filename }} ?">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <button type="submit" class="px-3 py-1 rounded bg-red-600 text-white hover:bg-red-700">🗑️ Supprimer</button>
            </form>
          </div>
        </div>
        <div id="share-box-{{ f.id }}"></div>
      {% endfor %}
    </div>

    <!-- pagination -->
    <div class="flex items-center justify-center gap-1 mt-4">
      {% set prev = page-1 if page>1 else 1 %}
      {% set next = page+1 if page<total_pages else total_pages %}
      <button class="px-2 py-1 border rounded" hx-get="{{ url_for('main.filter_files') }}"
              hx-include="#search-form"
              hx-vals='{"sort":"{{ sort }}","dir":"{{ direction }}","page":1,"per_page":{{ per_page }}}'
              hx-target="#files-list" hx-swap="outerHTML">«</button>
      <button class="px-2 py-1 border rounded" hx-get="{{ url_for('main.filter_files') }}"
              hx-include="#search-form"
              hx-vals='{"sort":"{{ sort }}","dir":"{{ direction }}","page":{{ prev }},"per_page":{{ per_page }}}'
              hx-target="#files-list" hx-swap="outerHTML">‹</button>

      {% for p in range(1, total_pages+1) %}
        {% if p == page %}
          <span class="px-2 py-1 border rounded bg-gray-200">{{ p }}</span>
        {% elif p <= 3 or p > total_pages-3 or (p >= page-1 and p <= page+1) %}
          <button class="px-2 py-1 border rounded" hx-get="{{ url_for('main.filter_files') }}"
                  hx-include="#search-form"
                  hx-vals='{"sort":"{{ sort }}","dir":"{{ direction }}","page":{{ p }},"per_page":{{ per_page }}}'
                  hx-target="#files-list" hx-swap="outerHTML">{{ p }}</button>
        {% elif p == 4 and page > 5 %}
          <span class="px-2">…</span>
        {% elif p == total_pages-3 and page < total_pages-4 %}
          <span class="px-2">…</span>
        {% endif %}
      {% endfor %}

      <button class="px-2 py-1 border rounded" hx-get="{{ url_for('main.filter_files') }}"
              hx-include="#search-form"
              hx-vals='{"sort":"{{ sort }}","dir":"{{ direction }}","page":{{ next }},"per_page":{{ per_page }}}'
              hx-target="#files-list" hx-swap="outerHTML">›</button>
      <button class="px-2 py-1 border rounded" hx-get="{{ url_for('main.filter_files') }}"
              hx-include="#search-form"
              hx-vals='{"sort":"{{ sort }}","dir":"{{ direction }}","page":{{ total_pages }},"per_page":{{ per_page }}}'
              hx-target="#files-list" hx-swap="outerHTML">»</button>
    </div>
  {% else %}
    <div class="bg-white shadow rounded p-4 text-gray-500 italic">Aucun résultat.</div>
  {% endif %}
</div>
    """,
    files=files, shares_map={},  # plus utilisé ici
    page=page, total_pages=total_pages, per_page=per_page,
    sort=sort, direction=direction, total=total
)


# ---------------------------
# Suggestions (mes fichiers)
# ---------------------------
@main_bp.get("/files/suggest")
@login_required
def suggest_files():
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return render_template_string('<div id="suggestions"></div>')

    like = f"%{q}%"
    order_by_col = _order_col().desc()
    results = (
        db.session.query(EncryptedFile.id, EncryptedFile.filename)
        .filter(EncryptedFile.user_id == current_user.id,
                EncryptedFile.filename.ilike(like))
        .order_by(order_by_col)
        .limit(8)
        .all()
    )

    fragment = """
    <div id="suggestions" class="absolute z-40 bg-white border rounded w-full md:w-1/2 mt-1 shadow">
      {% for fid, name in results %}
        <a class="block w-full text-left px-3 py-2 hover:bg-gray-100"
           href="#"
           hx-get="{{ url_for('main.filter_files') }}"
           hx-include="#search-form"
           hx-vals='{"q": {{ name|tojson }}, "page": 1}'
           hx-target="#files-list"
           hx-swap="outerHTML"
           data-clear-suggestions="true"
           onclick="var i=document.querySelector('#search-form input[name=q]'); if(i){i.value={{ name|tojson }};} return false;">
           {{ name }}
        </a>
      {% else %}
        <div class="px-3 py-2 text-gray-500">Aucun résultat</div>
      {% endfor %}
    </div>
    """
    return render_template_string(fragment, results=results)

# ============================================================
#      ⬇️ OPTION A (prix par lot) pour PARTAGES & MES FICHIERS ⬇️
# ============================================================

@main_bp.route("/shared", methods=["GET"])
@login_required
def shared_list():
    _ensure_logger()

    category = request.args.get("category", "Tous")
    q = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "date")
    direction = request.args.get("dir", "desc")
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = int(request.args.get("per_page", 20) or 20)

    base = (
        db.session.query(EncryptedFile)
        .join(FileShare, FileShare.file_id == EncryptedFile.id)
        .filter(FileShare.shared_with_user_id == current_user.id)
    )

    raw_counts = (
        base.with_entities(EncryptedFile.category, func.count(EncryptedFile.id))
        .group_by(EncryptedFile.category)
        .all()
    )
    counts = {c: n for c, n in raw_counts}
    total_all = sum(counts.values())
    categories = ["Tous", "Document", "Image", "Audio", "Vidéo", "Logiciel", "Archive", "Autre"]
    cats_with_counts = [(cat, total_all if cat == "Tous" else counts.get(cat, 0)) for cat in categories]

    query = base
    if category and category != "Tous":
        query = query.filter(EncryptedFile.category == category)
    if q:
        like = f"%{q}%"
        query = query.filter(EncryptedFile.filename.ilike(like))

    total = query.count()
    total_pages = max(math.ceil(total / per_page), 1)
    query = _apply_sort(query, sort, direction)
    files = query.limit(per_page).offset((page - 1) * per_page).all()

    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))

    return render_template(
        "shared.html",
        files=files,
        my_credits=int(current_user.credits or 0),
        palier_mo=palier_mo,
        session_fee=session_fee,
        cats_with_counts=cats_with_counts,
        selected_category=category,
        q=q, sort=sort, direction=direction,
        page=page, total_pages=total_pages, per_page=per_page
    )

@main_bp.get("/shared/suggest")
@login_required
def shared_suggest():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return render_template_string('<div id="suggestions"></div>')
    like = f"%{q}%"
    order_by_col = _order_col().desc()
    results = (
        db.session.query(EncryptedFile.id, EncryptedFile.filename)
        .join(FileShare, FileShare.file_id == EncryptedFile.id)
        .filter(FileShare.shared_with_user_id == current_user.id,
                EncryptedFile.filename.ilike(like))
        .order_by(order_by_col)
        .limit(8)
        .all()
    )
    return render_template_string(
        """
    <div id="suggestions" class="absolute z-40 bg-white border rounded w-full md:w-1/2 mt-1 shadow">
      {% for fid, name in results %}
        <a class="block w-full text-left px-3 py-2 hover:bg-gray-100"
           href="{{ url_for('main.shared_list') }}?q={{ name|urlencode }}"
           data-clear-suggestions="true">{{ name }}</a>
      {% else %}
        <div class="px-3 py-2 text-gray-500">Aucun résultat</div>
      {% endfor %}
    </div>
        """,
        results=results
    )

@main_bp.route("/shared/unshare/<int:file_id>", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def shared_unshare(file_id):
    _ensure_logger()
    row = FileShare.query.filter_by(file_id=file_id, shared_with_user_id=current_user.id).first()
    if not row:
        flash("Aucun partage à retirer pour ce fichier.", "warning")
        return redirect(url_for("main.shared_list"))
    try:
        db.session.delete(row)
        db.session.commit()
        flash("Partage retiré ✅", "success")
        admin_logger.info(f"{current_user.username} a retiré un partage file_id={file_id}")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors du retrait du partage : {str(e)} ❌", "danger")
    return redirect(url_for("main.shared_list"))

@main_bp.route("/shared/estimate", methods=["GET"])
@login_required
def shared_estimate():
    _ensure_logger()
    ids = _parse_ids_arg()
    if not ids:
        flash("Veuillez sélectionner au moins un fichier.", "warning")
        return redirect(url_for("main.shared_list"))

    files = EncryptedFile.query.filter(EncryptedFile.id.in_(ids)).all()
    files = _filter_accessible(files)
    if not files:
        flash("Aucun fichier accessible dans la sélection.", "danger")
        return redirect(url_for("main.shared_list"))

    total_bytes = _sum_bytes(files)
    needed = _calc_credits_cost(total_bytes)
    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))
    total_mo = total_bytes / float(1024 * 1024)
    flash(
        f"Estimation : {len(files)} fichier(s), ~{total_mo:.2f} Mo → {needed} crédit(s). "
        f"Formule : {session_fee} (session) + 1 crédit / {palier_mo} Mo.",
        "info"
    )
    return redirect(url_for("main.shared_list"))

@main_bp.route("/shared/download/selected", methods=["GET"])
@login_required
@limiter.limit("30 per hour")
def shared_download_selected():
    _ensure_logger()
    ids = _parse_ids_arg()
    if not ids:
        flash("Veuillez sélectionner au moins un fichier.", "warning")
        return redirect(url_for("main.shared_list"))

    files = EncryptedFile.query.filter(EncryptedFile.id.in_(ids)).all()
    files = _filter_accessible(files)
    if not files:
        flash("Aucun fichier accessible dans la sélection.", "danger")
        return redirect(url_for("main.shared_list"))

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(total_bytes, label="shared_selected", file_ids=[f.id for f in files])
    if charge_result is not True:
        return charge_result

    mem = BytesIO()
    with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            try:
                plaintext = decrypt_file_hybrid(f.ciphertext, f.encrypted_key, f.nonce, f.tag)
                zf.writestr(secure_filename(f.filename) or f"file_{f.id}", plaintext)
            except Exception as e:
                zf.writestr(f"ERROR_{f.id}.txt", f"Erreur de déchiffrement: {str(e)}")
    mem.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    admin_logger.info(f"{current_user.username} a téléchargé {len(files)} fichiers (lot sélection) — Option A")
    return send_file(mem, as_attachment=True, download_name=f"partage_selection_{ts}.zip", mimetype="application/zip")

@main_bp.route("/shared/download/all", methods=["GET"])
@login_required
@limiter.limit("15 per hour")
def shared_download_all():
    _ensure_logger()
    files = (
        db.session.query(EncryptedFile)
        .join(FileShare, FileShare.file_id == EncryptedFile.id)
        .filter(FileShare.shared_with_user_id == current_user.id)
        .all()
    )
    files = _filter_accessible(files)
    if not files:
        flash("Aucun fichier partagé à télécharger.", "info")
        return redirect(url_for("main.shared_list"))

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(total_bytes, label="shared_all", file_ids=[f.id for f in files])
    if charge_result is not True:
        return charge_result

    mem = BytesIO()
    with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            try:
                plaintext = decrypt_file_hybrid(f.ciphertext, f.encrypted_key, f.nonce, f.tag)
                zf.writestr(secure_filename(f.filename) or f"file_{f.id}", plaintext)
            except Exception as e:
                zf.writestr(f"ERROR_{f.id}.txt", f"Erreur de déchiffrement: {str(e)}")
    mem.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    admin_logger.info(f"{current_user.username} a téléchargé {len(files)} fichiers (lot tout) — Option A")
    return send_file(mem, as_attachment=True, download_name=f"partage_tout_{ts}.zip", mimetype="application/zip")

@main_bp.route("/shared/download/one/<int:file_id>", methods=["GET"])
@login_required
@limiter.limit("60 per hour")
def shared_download_one(file_id):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not _has_access(enc_file, current_user):
        flash("Accès non autorisé à ce fichier partagé ❌", "danger")
        return redirect(url_for("main.shared_list"))

    total_bytes = len(getattr(enc_file, "ciphertext", b"") or b"")
    charge_result = _charge_option_a_or_redirect(total_bytes, label="shared_one", file_ids=[enc_file.id])
    if charge_result is not True:
        return charge_result

    try:
        plaintext = decrypt_file_hybrid(
            enc_file.ciphertext,
            enc_file.encrypted_key,
            enc_file.nonce,
            enc_file.tag
        )
        tmp_file = BytesIO(plaintext); tmp_file.seek(0)
        admin_logger.info(f"{current_user.username} a téléchargé {enc_file.filename} (unitaire partagé) — Option A")
        mime_type = getattr(enc_file, "content_type", None) or mimetypes.guess_type(enc_file.filename)[0]
        return send_file(tmp_file, as_attachment=True, download_name=enc_file.filename, mimetype=mime_type or "application/octet-stream")
    except Exception as e:
        flash(f"Erreur lors du déchiffrement : {str(e)} ❌", "danger")
        return redirect(url_for("main.shared_list"))

@main_bp.route("/shared/download/selected/links", methods=["GET"])
@login_required
@limiter.limit("30 per hour")
def shared_download_selected_links():
    _ensure_logger()
    ids = _parse_ids_arg()
    if not ids:
        return jsonify({"ok": False, "error": "no_selection"}), 400

    files = EncryptedFile.query.filter(EncryptedFile.id.in_(ids)).all()
    files = _filter_accessible(files)
    if not files:
        return jsonify({"ok": False, "error": "no_accessible_files"}), 403

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(
        total_bytes,
        label="shared_selected_links",
        file_ids=[f.id for f in files]
    )
    if charge_result is not True:
        return charge_result  # JSON 402

    for f in files:
        token = sign_download_token(file_id=f.id, user_id=current_user.id)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        exists = db.session.query(DownloadToken.id).filter_by(token_hash=token_hash).first()
        if not exists:
            db.session.add(DownloadToken(token_hash=token_hash, file_id=f.id, user_id=current_user.id))
    db.session.commit()

    links = []
    for f in files:
        token = sign_download_token(file_id=f.id, user_id=current_user.id)
        links.append(url_for("main.download_with_token", token=token, _external=True))

    admin_logger.info(
        f"{current_user.username} a lancé {len(links)} téléchargements séparés (Option A | liens) "
        f"total_bytes={total_bytes} files={ids}"
    )
    return jsonify({"ok": True, "count": len(links), "links": links})

# ---------------------------
# (7) — BULK “MES FICHIERS”
# ---------------------------
@main_bp.get("/my/download/selected")
@login_required
@limiter.limit("30 per hour")
def my_download_selected():
    """Télécharger en ZIP la sélection de MES fichiers (débit Option A)."""
    _ensure_logger()
    ids = _parse_ids_arg()
    if not ids:
        flash("Veuillez sélectionner au moins un fichier.", "warning")
        return redirect(url_for("main.files"))

    files = EncryptedFile.query.filter(EncryptedFile.id.in_(ids)).all()
    files = [f for f in files if f.user_id == current_user.id]
    if not files:
        flash("Aucun fichier valide dans la sélection.", "danger")
        return redirect(url_for("main.files"))

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(total_bytes, label="my_selected", file_ids=[f.id for f in files])
    if charge_result is not True:
        return charge_result

    # Construction ZIP via util streamable
    zip_fp, zip_name = build_zip_file(files, decrypt_fn=lambda f: decrypt_file_hybrid(f.ciphertext, f.encrypted_key, f.nonce, f.tag))
    admin_logger.info(f"{current_user.username} a téléchargé {len(files)} fichiers (MES sélection) — Option A")
    return send_file(zip_fp, as_attachment=True, download_name=zip_name, mimetype="application/zip")

@main_bp.get("/my/download/all")
@login_required
@limiter.limit("15 per hour")
def my_download_all():
    """Télécharger en ZIP TOUS MES fichiers (débit Option A)."""
    _ensure_logger()
    files = db.session.query(EncryptedFile).filter(EncryptedFile.user_id == current_user.id).all()
    if not files:
        flash("Aucun fichier à télécharger.", "info")
        return redirect(url_for("main.files"))

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(total_bytes, label="my_all", file_ids=[f.id for f in files])
    if charge_result is not True:
        return charge_result

    zip_fp, zip_name = build_zip_file(files, decrypt_fn=lambda f: decrypt_file_hybrid(f.ciphertext, f.encrypted_key, f.nonce, f.tag))
    admin_logger.info(f"{current_user.username} a téléchargé {len(files)} fichiers (MES tout) — Option A")
    return send_file(zip_fp, as_attachment=True, download_name=zip_name, mimetype="application/zip")

@main_bp.get("/my/download/selected/links")
@login_required
@limiter.limit("30 per hour")
def my_download_selected_links():
    """Téléchargements séparés (liens signés) pour MES fichiers sélectionnés (débit unique Option A)."""
    _ensure_logger()
    ids = _parse_ids_arg()
    if not ids:
        return jsonify({"ok": False, "error": "no_selection"}), 400

    files = EncryptedFile.query.filter(EncryptedFile.id.in_(ids)).all()
    files = [f for f in files if f.user_id == current_user.id]
    if not files:
        return jsonify({"ok": False, "error": "no_accessible_files"}), 403

    total_bytes = _sum_bytes(files)
    charge_result = _charge_option_a_or_redirect(total_bytes, label="my_selected_links", file_ids=[f.id for f in files])
    if charge_result is not True:
        return charge_result  # JSON 402 si crédits insuffisants

    for f in files:
        token = sign_download_token(file_id=f.id, user_id=current_user.id)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        exists = db.session.query(DownloadToken.id).filter_by(token_hash=token_hash).first()
        if not exists:
            db.session.add(DownloadToken(token_hash=token_hash, file_id=f.id, user_id=current_user.id))
    db.session.commit()

    links = []
    for f in files:
        token = sign_download_token(file_id=f.id, user_id=current_user.id)
        links.append(url_for("main.download_with_token", token=token, _external=True))

    admin_logger.info(
        f"{current_user.username} a lancé {len(links)} téléchargements séparés (MES fichiers | liens) "
        f"total_bytes={total_bytes} files={ids}"
    )
    return jsonify({"ok": True, "count": len(links), "links": links})

# ---------- (5) Formulaire inline → route GET qui renvoie le partial ----------
@main_bp.get("/share/<int:file_id>/inline")
@login_required
def share_inline_form(file_id: int):
    _ensure_logger()
    enc_file = EncryptedFile.query.get_or_404(file_id)
    if not current_user.is_admin() and enc_file.user_id != current_user.id:
        return render_template_string('<div class="text-sm text-red-700">Accès non autorisé ❌</div>')
    return render_template("partials/share_inline_form.html", file=enc_file)

# Page “Mes fichiers” (shell)
@main_bp.route("/files", methods=["GET"])
@login_required
def files():
    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))
    return render_template("files.html", palier_mo=palier_mo, session_fee=session_fee)

# ---------------------------
# Suppression du compte (self-delete)
# ---------------------------
@main_bp.get("/me/delete/modal")
@login_required
def me_delete_modal():
    # Vérifie s'il serait le dernier admin
    last_admin = False
    try:
        from app.models.user import User
        admins = [u for u in User.query.all() if (u.is_admin() if callable(getattr(u, "is_admin", None)) else getattr(u, "role", "") == "admin")]
        if len(admins) == 1 and admins[0].id == current_user.id:
            last_admin = True
    except Exception:
        pass

    return render_template("modals/confirm_self_delete.html", last_admin=last_admin)

@main_bp.post("/me/delete")
@login_required
@limiter.limit("10/hour")
def me_delete():
    from app.models.user import User

    password = (request.form.get("password") or "").strip()
    if not password:
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Mot de passe requis.","danger");</script>'
        ), 400

    # Empêcher la suppression du dernier admin
    admins = [u for u in User.query.all()
              if (u.is_admin() if callable(getattr(u, "is_admin", None))
                  else (getattr(u, "role", "") == "admin"))]
    if len(admins) == 1 and admins[0].id == current_user.id:
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Impossible de supprimer le dernier administrateur.","danger");</script>'
        ), 400

    # Vérifier le mot de passe (gère check_password & hash direct)
    is_valid = False
    try:
        if hasattr(current_user, "check_password") and callable(current_user.check_password):
            is_valid = current_user.check_password(password)
        else:
            pwd_hash = getattr(current_user, "password_hash", None) or getattr(current_user, "password", None)
            if pwd_hash:
                try:
                    is_valid = check_password_hash(pwd_hash, password)
                except Exception:
                    # si password en clair (pas idéal, mais évite un 500)
                    is_valid = (pwd_hash == password)
    except Exception:
        is_valid = False

    if not is_valid:
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Mot de passe invalide.","danger");</script>'
        ), 400

    uid = current_user.id
    try:
        u = User.query.get(uid)
        if not u:
            return render_template_string(
                '<div id="modal-root"></div><script>window.showToast("Utilisateur introuvable.","danger");</script>'
            ), 404

        # (optionnel) journaliser l’action dans l’audit
        try:
            log_account_deletion(user_id=uid, meta={"by": "self"})
        except Exception:
            pass

        delete_user_cascade(u)
        db.session.commit()

        # Déconnexion (si utilisée)
        try:
            from flask_login import logout_user
            logout_user()
        except Exception:
            pass

        # Nettoie la modale et redirige côté client
        return render_template_string("""
          <div id="modal-root" hx-swap-oob="true"></div>
          <script>
            try { window.showToast && window.showToast("Compte supprimé. Au revoir 👋","success"); } catch(_){}
            window.setTimeout(function(){ window.location = {{ url_for('main.index')|tojson }}; }, 300);
          </script>
        """)
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Self delete failed")
        return render_template_string(
            '<div id="modal-root"></div><script>window.showToast("Suppression impossible (voir logs).","danger");</script>'
        ), 500



@main_bp.route("/legal/privacy")
def legal_privacy():
    return render_template("legal/privacy.html")
