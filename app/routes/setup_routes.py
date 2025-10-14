# app/routes/setup_routes.py
from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, abort, jsonify
from app.extensions import db, csrf
from app.models.user import User
from werkzeug.security import generate_password_hash

setup_bp = Blueprint(
    "setup",
    __name__,
    template_folder="../templates/setup",
)

def _has_admin() -> bool:
    try:
        if hasattr(User, "role"):
            try:
                if User.query.filter((User.role == "admin") | (User.role == "ADMIN") | (User.role == "Admin")).first():
                    return True
            except Exception:
                try:
                    if User.query.filter(User.role.ilike("admin")).first():
                        return True
                except Exception:
                    pass
        if hasattr(User, "is_admin"):
            try:
                if User.query.filter_by(is_admin=True).first():
                    return True
            except Exception:
                pass
        return False
    except Exception:
        return False

def _safe_set(obj, attr: str, value) -> bool:
    try:
        setattr(obj, attr, value)
        return True
    except Exception:
        return False

def _require_token():
    token = request.args.get("token") or request.form.get("token")
    expected = current_app.config.get("SETUP_BOOTSTRAP_TOKEN", "")
    if not expected or token != expected:
        abort(403)
    return token

@setup_bp.route("/status", methods=["GET"])
@csrf.exempt
def status():
    _require_token()
    try:
        total_users = User.query.count()
    except Exception:
        total_users = 0
    return jsonify({
        "admin_exists": _has_admin(),
        "users_count": total_users,
        "hints": [
            "Si admin_exists = true, la page /setup/first-admin renverra 404 (par design).",
            "Si admin_exists = false, tu peux créer le premier admin via /setup/first-admin?token=mon_token_ultra_long_et_dur",
        ]
    })

@setup_bp.route("/first-admin", methods=["GET", "POST"])
@csrf.exempt
def first_admin():
    token = _require_token()

    if _has_admin():
        abort(404)

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        username = (request.form.get("username") or "").strip() or (email.split("@")[0] if "@" in email else "admin")
        password = (request.form.get("password") or "").strip()

        if not email or not password:
            flash("Email et mot de passe sont requis.", "danger")
            return render_template("setup/first_admin.html", token=token)

        u = User(email=email, username=username)

        if hasattr(u, "set_password"):
            u.set_password(password)
        elif hasattr(u, "password_hash"):
            u.password_hash = generate_password_hash(password)
        else:
            _safe_set(u, "password", password)

        if hasattr(u, "role"):
            _safe_set(u, "role", "admin")
        if hasattr(u, "is_admin"):
            _safe_set(u, "is_admin", True)

        for attr in ("two_factor_enabled", "is_2fa_enabled", "otp_enabled"):
            if hasattr(u, attr):
                _safe_set(u, attr, False)
        for attr in ("otp_secret", "two_factor_secret", "totp_secret"):
            if hasattr(u, attr):
                _safe_set(u, attr, None)

        db.session.add(u)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la création: {e}", "danger")
            return render_template("setup/first_admin.html", token=token)

        flash("✅ Admin créé. Connectez-vous maintenant.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup/first_admin.html", token=token)
