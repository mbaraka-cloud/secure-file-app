# app/__init__.py
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, flash, redirect, url_for, session, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import event

from .extensions import db, login_manager, csrf, limiter, migrate, talisman
from .routes.main_routes import main_bp
from .routes.admin_routes import admin_bp
from .routes.auth_routes import auth_bp
from .routes.stripe_routes import bp as stripe_bp
from .routes.billing_routes import bp as billing_bp

from .utils.logging_config import setup_logging
from config import Config


def create_app(config_name: str | None = None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    # Token bootstrap setup (si présent => active /setup)
    app.config["SETUP_BOOTSTRAP_TOKEN"] = os.environ.get("SETUP_BOOTSTRAP_TOKEN", "")

    # Proxy (HTTPS derrière Nginx)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # === Extensions ===
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)

    # Import des modèles (pour migrations & shell)
    from . import models as _models  # noqa: F401

    # SQLite : activer FK si jamais sqlite est utilisé
    with app.app_context():
        if db.engine.url.drivername.startswith("sqlite"):
            @event.listens_for(db.engine, "connect")
            def _set_sqlite_pragma(dbapi_con, con_record):
                try:
                    cur = dbapi_con.cursor()
                    cur.execute("PRAGMA foreign_keys=ON")
                    cur.close()
                    app.logger.info("[DB] PRAGMA foreign_keys=ON")
                except Exception as e:
                    app.logger.warning("[DB] Impossible d'activer les FK : %s", e)

    # === Sécurité (CSP/Talisman) ===
    default_csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://unpkg.com", "https://cdn.jsdelivr.net", "https://js.stripe.com"],
        "style-src": ["'self'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'", "https://api.stripe.com"],
        "frame-src": ["'self'", "https://js.stripe.com", "https://checkout.stripe.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
        "frame-ancestors": ["'none'"],
    }
    csp = app.config.get("TALISMAN_CONTENT_SECURITY_POLICY", default_csp)

    use_ssl = os.environ.get("USE_SSL", "false").lower() in ("1", "true", "yes")
    force_https_cfg = bool(app.config.get("TALISMAN_FORCE_HTTPS", False))
    force_https = use_ssl or force_https_cfg

    talisman.init_app(
        app,
        content_security_policy=csp,
        force_https=force_https,
        strict_transport_security=force_https,
        session_cookie_secure=force_https,
    )

    # === Logging ===
    setup_logging(app)

    # Logger dédié aux actions admin (fichier séparé)
    try:
        admin_logger = logging.getLogger("admin_actions")
        admin_logger.setLevel(logging.INFO)
        log_dir = app.config.get("LOG_DIR", os.path.join(app.root_path, "..", "logs"))
        os.makedirs(log_dir, exist_ok=True)
        fh = RotatingFileHandler(os.path.join(log_dir, "admin_actions.log"), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        admin_logger.addHandler(fh)
        app.config["ADMIN_ACTION_LOGGER_NAME"] = "admin_actions"
    except Exception as e:
        app.logger.warning("Impossible d'initialiser admin_actions logger: %s", e)
        app.config["ADMIN_ACTION_LOGGER_NAME"] = None

    @app.before_request
    def _make_session_permanent():
        session.permanent = True

    # === Blueprints ===
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(stripe_bp)
    app.register_blueprint(billing_bp)

    # Setup (facultatif, activé si token)
    if app.config.get("SETUP_BOOTSTRAP_TOKEN"):
        try:
            from .routes.setup_routes import setup_bp  # type: ignore
            app.register_blueprint(setup_bp, url_prefix="/setup")
            app.logger.info("[BOOT] setup_bp enregistré (URL /setup/*)")
        except Exception as e:
            app.logger.warning("[BOOT] Impossible d’enregistrer setup_bp: %s", e)
    else:
        app.logger.info("[BOOT] setup_bp non enregistré (pas de token)")

    # Healthcheck (réponse 200, sans login)
    try:
        from app.routes.health import health_bp
        app.register_blueprint(health_bp)
        # CSRF/limiter exemptés dans le module
        app.logger.info("[BOOT] health_bp enregistré (URL /healthz)")
    except Exception as e:
        app.logger.warning(f"[BOOT] Échec enregistrement health_bp: {e}")

    # Account (optionnel)
    try:
        from .routes.account_routes import account_bp  # type: ignore
        app.register_blueprint(account_bp)
    except Exception:
        pass

    # Webhooks Stripe : pas de CSRF
    try:
        csrf.exempt(stripe_bp)
    except Exception:
        pass

    # === Login ===
    login_manager.login_view = "auth.login"

    @app.errorhandler(429)
    def ratelimit_handler(e):
        flash("⏳ Trop de tentatives. Réessayez dans quelques instants.", "danger")
        return redirect(url_for("auth.login"))

    # === Pages d'erreur jolies + log ===
    @app.errorhandler(403)
    def _err_403(e):
        app.logger.warning("403 on %s (UA=%s)", request.path, request.headers.get("User-Agent"))
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def _err_404(e):
        app.logger.info("404 on %s", request.path)
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def _err_500(e):
        app.logger.exception("500 on %s", request.path)
        return render_template("errors/500.html"), 500

    @app.shell_context_processor
    def make_shell_context():
        from .models.user import User
        from .models.purchase import Purchase
        from .models.credit_usage import CreditUsage
        try:
            from .models.download_token import DownloadToken
        except Exception:
            DownloadToken = None  # type: ignore
        try:
            from .models.billing_event import BillingEvent
        except Exception:
            BillingEvent = None  # type: ignore
        return {
            "db": db,
            "User": User,
            "Purchase": Purchase,
            "CreditUsage": CreditUsage,
            "DownloadToken": DownloadToken,
            "BillingEvent": BillingEvent,
        }

    env_name = app.config.get("ENV", "production")
    app.logger.info(f"[BOOT] ENV={env_name} | DB URI: {app.config.get('SQLALCHEMY_DATABASE_URI')}")
    app.logger.info(f"[BOOT] HTTPS forced? {force_https} | CSP keys: {list(csp.keys()) if isinstance(csp, dict) else 'custom'}")
    app.logger.info(f"[BOOT] Blueprints: {list(app.blueprints.keys())}")

    return app
