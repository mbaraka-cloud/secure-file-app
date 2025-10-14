# app/routes/auth_routes.py
import base64
import io
import time
from datetime import timedelta, datetime

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, limiter, csrf
from app.models.user import User
from app.forms.forms import LoginForm, RegisterForm, TwoFactorCodeForm, Enable2FAForm

# (8) reset password
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets
from app.utils.email_utils import send_email

# ==== imports pour la suppression de compte (self-delete) ====
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import json

# Blueprint auth
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# --- Paramètres de protection brute force ---
MAX_FAILED_ATTEMPTS = 5
BAN_SECONDS = 10 * 60  # 10 minutes

# --- Helpers reset ---
def _get_serializer() -> URLSafeTimedSerializer:
    secret_key = current_app.config.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY manquant pour générer les tokens de reset.")
    return URLSafeTimedSerializer(secret_key, salt=current_app.config.get("SECURITY_PASSWORD_SALT", "pwdreset-salt"))

def _make_reset_token(user: User) -> str:
    s = _get_serializer()
    nonce = secrets.token_urlsafe(8)
    return s.dumps({"uid": user.id, "email": user.email, "n": nonce})

def _verify_reset_token(token: str, max_age_seconds: int = None):
    s = _get_serializer()
    if max_age_seconds is None:
        max_age_seconds = int(current_app.config.get("PASSWORD_RESET_TOKEN_MAX_AGE", 3600))
    try:
        data = s.loads(token, max_age=max_age_seconds)
        return data
    except (SignatureExpired, BadSignature):
        return None


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.banned_until = int(time.time()) + BAN_SECONDS
                    user.failed_attempts = 0
                db.session.commit()
            flash("Email ou mot de passe incorrect ❌", "danger")
            return render_template("auth/login.html", form=form)

        if user.is_banned():
            flash("Trop de tentatives échouées. Réessayez plus tard ⛔", "danger")
            return render_template("auth/login.html", form=form)

        user.failed_attempts = 0
        db.session.commit()

        if user.two_factor_enabled and user.two_factor_secret:
            session["2fa_user_id"] = user.id
            return redirect(url_for("auth.verify_2fa"))
        else:
            login_user(user, remember=True, duration=timedelta(days=7))
            flash("Connexion réussie ✅", "success")
            return redirect(url_for("admin.dashboard") if user.is_admin() else url_for("main.index"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_2fa():
    form = TwoFactorCodeForm()
    user = User.query.get(session.get("2fa_user_id"))

    if not user:
        session.pop("2fa_user_id", None)
        flash("Session expirée. Veuillez vous reconnecter ❌", "danger")
        return redirect(url_for("auth.login"))

    if form.validate_on_submit():
        token = form.token.data.strip()
        if pyotp.TOTP(user.two_factor_secret).verify(token, valid_window=1):
            login_user(user, remember=True, duration=timedelta(days=7))
            session.pop("2fa_user_id", None)
            flash("Connexion 2FA réussie ✅", "success")
            return redirect(url_for("admin.dashboard") if user.is_admin() else url_for("main.index"))
        else:
            flash("Code invalide ❌", "danger")

    return render_template("auth/verify_2fa.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        # Consentement obligatoire
        privacy_accept = request.form.get("privacy_accept")
        if not privacy_accept:
            flash("Vous devez accepter la Politique de confidentialité pour créer un compte ❌", "danger")
            return render_template("auth/register.html", form=form)

        if User.query.filter_by(email=email).first():
            flash("Email déjà utilisé ❌", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris ❌", "danger")
        else:
            new_user = User(username=username, email=email)
            new_user.set_password(password)

            # Champs optionnels
            new_user.first_name = (request.form.get("first_name") or "").strip() or None
            new_user.last_name = (request.form.get("last_name") or "").strip() or None
            new_user.phone = (request.form.get("phone") or "").strip() or None

            # Horodatage d’acceptation
            new_user.privacy_accepted_at = datetime.utcnow()

            db.session.add(new_user)
            db.session.commit()
            flash("Inscription réussie ✅", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/enable-2fa", methods=["GET", "POST"])
@login_required
def enable_2fa():
    """
    Génère un secret TOTP et un QR-code.
    - Tente PNG si Pillow est dispo.
    - Fallback en SVG si Pillow manque.
    - Dernier recours : affiche l’URI otpauth:// en clair.
    """
    form = Enable2FAForm()
    user = current_user

    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()
        db.session.commit()

    otp_uri = pyotp.totp.TOTP(user.two_factor_secret).provisioning_uri(
        name=user.email, issuer_name="SecureFileApp"
    )

    qr_src = None
    try:
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_src = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")
    except Exception:
        try:
            from qrcode.image.svg import SvgImage
            img = qrcode.make(otp_uri, image_factory=SvgImage)
            buf = io.BytesIO()
            img.save(buf)
            svg_text = buf.getvalue().decode("utf-8")
            qr_src = "data:image/svg+xml;base64," + base64.b64encode(svg_text.encode("utf-8")).decode("utf-8")
        except Exception:
            qr_src = None

    return render_template("auth/enable_2fa.html", qr_code=qr_src, otp_uri=otp_uri, form=form)


@auth_bp.route("/confirm-enable-2fa", methods=["POST"])
@login_required
def confirm_enable_2fa():
    code = request.form.get("code", "").strip()
    if not code or not code.isdigit() or len(code) != 6:
        flash("Code invalide ❌", "danger")
        return redirect(url_for("auth.enable_2fa"))

    totp = pyotp.TOTP(current_user.two_factor_secret)
    if totp.verify(code, valid_window=1):
        current_user.two_factor_enabled = True
        db.session.commit()
        flash("2FA activée avec succès ✅", "success")
    else:
        flash("Code incorrect ❌", "danger")
    return redirect(url_for("main.index"))


@auth_bp.route("/disable-2fa", methods=["POST"])
@login_required
@csrf.exempt
def disable_2fa():
    current_user.two_factor_enabled = False
    current_user.two_factor_secret = None
    db.session.commit()
    flash("2FA désactivée avec succès ❌", "info")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie 👋", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/get-flash")
def get_flash():
    return render_template("partials/flash_messages.html")


@auth_bp.route("/profile")
@login_required
def profile():
    return render_template("auth/profile.html")


# ==============================
# (8) Mot de passe oublié / reset
# ==============================

@auth_bp.route("/forgot", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = _make_reset_token(user)
                reset_url = url_for("auth.reset_password", token=token, _external=True)
                subject = "Réinitialisation de votre mot de passe"
                html = render_template("emails/reset_password.html", user=user, reset_url=reset_url, current_year=datetime.utcnow().year)
                send_email(to=email, subject=subject, html_body=html)
            except Exception:
                current_app.logger.exception("[auth] Impossible d'envoyer l'email de reset")

        flash("Si un compte existe pour cet email, un lien de réinitialisation a été envoyé 📧", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot.html")


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("15 per hour")
def reset_password(token):
    data = _verify_reset_token(token)
    if not data:
        flash("Lien invalide ou expiré ❌. Veuillez recommencer.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.get(data.get("uid"))
    if not user or user.email != data.get("email"):
        flash("Lien invalide ❌", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        pwd1 = (request.form.get("password") or "").strip()
        pwd2 = (request.form.get("password_confirm") or "").strip()
        if len(pwd1) < int(current_app.config.get("PASSWORD_MIN_LENGTH", 8)):
            flash("Mot de passe trop court (min 8 caractères) ❌", "danger")
            return render_template("auth/reset.html", token=token, email=user.email)
        if pwd1 != pwd2:
            flash("Les mots de passe ne correspondent pas ❌", "danger")
            return render_template("auth/reset.html", token=token, email=user.email)

        try:
            user.set_password(pwd1)
            db.session.commit()
            flash("Mot de passe mis à jour ✅. Vous pouvez vous connecter.", "success")
            return redirect(url_for("auth.login"))
        except Exception:
            db.session.rollback()
            flash("Erreur lors de la mise à jour du mot de passe ❌", "danger")
            return render_template("auth/reset.html", token=token, email=user.email)

    return render_template("auth/reset.html", token=token, email=user.email)


# ============================================================
#        SUPPRESSION DE COMPTE PAR L'UTILISATEUR (HTMX)
# ============================================================

# Helpers locaux (mêmes logiques que côté admin)
def _toast(message: str, variant: str = "success"):
    return {"toast": {"message": message, "variant": variant}}

def _set_hx_trigger(resp, payload: dict) -> None:
    safe = json.dumps(payload, separators=(",", ":")).replace("\r", "").replace("\n", "")
    resp.headers["HX-Trigger"] = safe

def _user_is_admin_local(u: User) -> bool:
    if hasattr(u, "is_admin"):
        try:
            return bool(u.is_admin() if callable(u.is_admin) else u.is_admin)
        except Exception:
            pass
    if hasattr(u, "role"):
        try:
            return (u.role or "").lower() == "admin"
        except Exception:
            pass
    return False

def _other_admins_exist_local(exclude_user_id: int) -> bool:
    # NB: petit volume attendu => simple boucle
    for uu in User.query.all():
        if uu.id != exclude_user_id and _user_is_admin_local(uu):
            return True
    return False


@auth_bp.get("/me/delete/modal")
@login_required
def me_delete_modal():
    """Affiche une modale de confirmation (appelée en HTMX)."""
    from app.models.encrypted_file import EncryptedFile  # import tardif pour éviter cycles
    files_count = db.session.query(EncryptedFile.id).filter_by(user_id=current_user.id).count()
    last_admin = _user_is_admin_local(current_user) and (not _other_admins_exist_local(current_user.id))
    return render_template(
        "modals/confirm_delete_self.html",
        u=current_user,
        files_count=files_count,
        last_admin=last_admin,
    )


@auth_bp.post("/me/delete")
@login_required
@limiter.limit("10/hour")
@csrf.exempt  # formulaires HTMX
def me_delete():
    """
    Supprime le compte courant (self-service) avec confirmation par mot de passe.
    Reprend l'ordre de purge qui marche côté admin.
    """
    log = current_app.logger
    log.info(f"[SELF] delete start user_id={current_user.id}")

    # ✅ NOUVEAU : confirmation par mot de passe (ne change rien au reste)
    pwd = (request.form.get("password") or "").strip()
    if not pwd or not current_user.check_password(pwd):
        resp = make_response("", 400)
        _set_hx_trigger(resp, _toast("Mot de passe incorrect ❌", "danger"))
        return resp

    u = User.query.get_or_404(current_user.id)

    # Interdire de supprimer le dernier admin (inchangé)
    if _user_is_admin_local(u) and not _other_admins_exist_local(u.id):
        resp = make_response("", 400)
        _set_hx_trigger(resp, _toast("Impossible : vous êtes le dernier administrateur.", "danger"))
        return resp

    # imports locaux pour éviter les cycles (inchangé)
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    import time, secrets
    from app.models.encrypted_file import EncryptedFile
    from app.models.file_share import FileShare
    from app.models.credit_usage import CreditUsage
    from app.models.purchase import Purchase
    from app.models.billing_event import BillingEvent

    try:
        # 1) Partages (propriétaire + reçu)
        FileShare.query.filter_by(owner_id=u.id).delete(synchronize_session=False)
        FileShare.query.filter_by(shared_with_user_id=u.id).delete(synchronize_session=False)
        db.session.flush()

        # 2) Tokens liés au user (tables héritées possibles)
        try:
            db.session.execute(text("DELETE FROM download_token WHERE user_id = :uid"), {"uid": u.id})
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[SELF] download_token by user_id skip: {e}")

        try:
            db.session.execute(text("DELETE FROM download_tokens WHERE user_id = :uid"), {"uid": u.id})
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[SELF] download_tokens by user_id skip: {e}")

        # 3) Tokens par fichier
        file_ids = [fid for (fid,) in db.session.query(EncryptedFile.id).filter_by(user_id=u.id).all()]
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

        # 4) Logs crédits/achats/audit
        try:
            CreditUsage.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[SELF] credit_usage skip: {e}")

        try:
            Purchase.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[SELF] purchase skip: {e}")

        try:
            BillingEvent.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            log.warning(f"[SELF] billing_event skip: {e}")

        # 5) Fichiers chiffrés
        for f in EncryptedFile.query.filter_by(user_id=u.id).all():
            db.session.delete(f)
        db.session.flush()

        # 6) Utilisateur
        db.session.delete(u)
        db.session.commit()

        # Déconnexion propre
        try:
            logout_user()
        except Exception:
            pass

        # Réponse HTMX : redirection vers l’accueil (inchangé)
        resp = make_response("", 204)
        _set_hx_trigger(resp, _toast("Compte supprimé. Au revoir 👋", "success"))
        resp.headers["HX-Redirect"] = url_for("main.index")
        return resp

    except IntegrityError:
        db.session.rollback()
        # Soft-delete de secours (inchangé)
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

            try:
                logout_user()
            except Exception:
                pass

            resp = make_response("", 204)
            _set_hx_trigger(resp, _toast("Compte anonymisé (soft delete).", "info"))
            resp.headers["HX-Redirect"] = url_for("main.index")
            return resp
        except Exception as e2:
            db.session.rollback()
            log.exception(f"[SELF] soft delete failed user_id={u.id}: {e2}")
            resp = make_response("", 500)
            _set_hx_trigger(resp, _toast("Erreur serveur pendant la suppression.", "danger"))
            return resp

    except Exception as e:
        db.session.rollback()
        log.exception(f"[SELF] delete unexpected error user_id={current_user.id}: {e}")
        resp = make_response("", 500)
        _set_hx_trigger(resp, _toast("Erreur serveur pendant la suppression.", "danger"))
        return resp
