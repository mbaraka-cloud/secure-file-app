import os
import json
from datetime import timedelta
from dotenv import load_dotenv

# Charge .env si présent (à la racine du projet)
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)   # pour SQLite locale
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def _env_str(key: str, default: str = "") -> str:
    """
    Récupère une variable d'env et la "nettoie" (strip espaces/guillemets/retours chariot).
    Utile pour éviter les erreurs Stripe dues à une clé collée avec des guillemets ou un \n.
    """
    val = os.getenv(key, default)
    if val is None:
        return default
    return val.strip().strip('"').strip("'").replace("\r", "").replace("\n", "")


class BaseConfig:
    # ===== Clé secrète / CSRF =====
    SECRET_KEY = _env_str("SECRET_KEY", "dev-key")
    WTF_CSRF_ENABLED = True

    # ===== Base de données =====
    SQLALCHEMY_DATABASE_URI = _env_str("DATABASE_URL") or (
        "sqlite:///" + os.path.join(INSTANCE_DIR, "app.db").replace(os.sep, "/")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ===== Session & Cookies =====
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = _env_str("SESSION_COOKIE_SAMESITE", "Strict")
    SESSION_COOKIE_SECURE = _env_str("SESSION_COOKIE_SECURE", "False") == "True"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = _env_str("REMEMBER_COOKIE_SECURE", "False") == "True"

    # ===== Dossiers =====
    UPLOAD_FOLDER = UPLOAD_DIR
    LOG_DIR = LOG_DIR

    # ===== Journalisation =====
    # Important: utiliser app.log pour le logger applicatif (l’“admin_actions.log” est géré séparément)
    LOG_FILE = os.path.join(LOG_DIR, "app.log")
    LOG_LEVEL = _env_str("LOG_LEVEL", "INFO")

    # ===== Uploads =====
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024 # 1 GB
    ALLOWED_EXTENSIONS = {
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "svg",
        "mp3", "m4a", "aac", "wav", "flac", "ogg", "opus", "wma", "aif", "aiff",
        "mp4", "m4v", "mkv", "avi", "mov", "wmv", "webm", "mpg", "mpeg", "3gp", "3gpp", "3g2",
        "pdf", "txt", "rtf", "md", "csv", "doc", "docx", "odt", "xls", "xlsx", "ods",
        "ppt", "pptx", "odp", "epub",
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
        "json", "xml", "yaml", "yml", "html", "htm", "css", "js", "ts", "py", "java", "c", "cpp", "cs", "go", "rb", "php",
    }

    # ===== RSA (chiffrement hybride) =====
    RSA_PUBLIC_KEY_PATH = _env_str("RSA_PUBLIC_KEY_PATH", os.path.join(BASE_DIR, "keys", "rsa_public.pem"))
    RSA_PRIVATE_KEY_PATH = _env_str("RSA_PRIVATE_KEY_PATH", os.path.join(BASE_DIR, "keys", "rsa_private.pem"))

    # ===== Stripe (paiement) =====
    STRIPE_SECRET_KEY = _env_str("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY = _env_str("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET = _env_str("STRIPE_WEBHOOK_SECRET", "")
    # STRIPE_PRICE_ID gardé pour compat éventuelle (non utilisé en mode dynamic price_data)
    STRIPE_PRICE_ID = _env_str("STRIPE_PRICE_ID", "")

    # URLs de retour (facultatives, sinon fallback dans la route)
    STRIPE_SUCCESS_URL = _env_str("STRIPE_SUCCESS_URL", "")
    STRIPE_CANCEL_URL  = _env_str("STRIPE_CANCEL_URL", "")

    # ===== Billing (crédits – Option A) =====
    BILLING_CREDIT_PALIER_MO = int(_env_str("BILLING_CREDIT_PALIER_MO", "500"))
    BILLING_SESSION_FEE_CREDITS = int(_env_str("BILLING_SESSION_FEE_CREDITS", "1"))

    # Fenêtre anti double-débit (idempotence côté session)
    BILLING_DEBIT_IDEMPOTENCY_WINDOW_SEC = int(_env_str("BILLING_DEBIT_IDEMPOTENCY_WINDOW_SEC", "20"))

    # Packs de crédits pour Stripe (montants en centimes) — format JSON :
    # [ [credits, amount_cents, "devise", "label"], ... ]
    BILLING_CREDIT_PACKS = json.loads(
        _env_str(
            "BILLING_CREDIT_PACKS_JSON",
            '[ [10,2000,"eur","Pack 10"], [25,4500,"eur","Pack 25"], [50,8000,"eur","Pack 50"] ]',
        )
    )

    # ===== Lien de téléchargement signé (compat legacy + TTL minutes) =====
    DOWNLOAD_TOKEN_TTL_MINUTES = int(_env_str("DOWNLOAD_TOKEN_TTL_MINUTES", "30"))
    _legacy_ttl_min = int(_env_str("BILLING_LOT_TOKEN_TTL_MIN", str(DOWNLOAD_TOKEN_TTL_MINUTES)))
    _legacy_ttl_from_seconds = int(int(_env_str("DOWNLOAD_TOKEN_EXP_SECONDS", "0")) / 60) if _env_str("DOWNLOAD_TOKEN_EXP_SECONDS", "") else 0
    if _legacy_ttl_from_seconds and _legacy_ttl_from_seconds > DOWNLOAD_TOKEN_TTL_MINUTES:
        DOWNLOAD_TOKEN_TTL_MINUTES = _legacy_ttl_from_seconds
    elif _legacy_ttl_min and _legacy_ttl_min > DOWNLOAD_TOKEN_TTL_MINUTES:
        DOWNLOAD_TOKEN_TTL_MINUTES = _legacy_ttl_min

    # ===== Quotas =====
    MAX_FILES_PER_USER = int(_env_str("MAX_FILES_PER_USER", "100"))
    MAX_TOTAL_BYTES_PER_USER = int(_env_str("MAX_TOTAL_BYTES_PER_USER", str(10 * 1024 * 1024 * 1024)))

    # ===== Flask-Limiter (stockage) =====
    LIMITER_STORAGE_URI = _env_str("LIMITER_STORAGE_URI", "memory://")
    RATELIMIT_STORAGE_URI = LIMITER_STORAGE_URI

    # --- bootstrap first admin ---
    SETUP_BOOTSTRAP_TOKEN = _env_str("SETUP_BOOTSTRAP_TOKEN", "")

    # ===== Reset mot de passe =====
    SECURITY_PASSWORD_SALT = _env_str("SECURITY_PASSWORD_SALT", "change-me")
    PASSWORD_RESET_TOKEN_MAX_AGE = int(_env_str("PASSWORD_RESET_TOKEN_MAX_AGE", "3600"))  # 1h par défaut
    PASSWORD_MIN_LENGTH = int(_env_str("PASSWORD_MIN_LENGTH", "8"))

    # ===== Email (utilisé par app/utils/email_utils.py) =====
    # MAIL_MODE: "smtp" | "console"
    MAIL_MODE = _env_str("MAIL_MODE", "console")
    MAIL_DEFAULT_SENDER = _env_str("MAIL_DEFAULT_SENDER", "no-reply@securefile.local")
    MAIL_SERVER = _env_str("MAIL_SERVER", "localhost")
    MAIL_PORT = int(_env_str("MAIL_PORT", "25"))
    MAIL_USE_TLS = _env_str("MAIL_USE_TLS", "False") == "True"
    MAIL_USE_SSL = _env_str("MAIL_USE_SSL", "False") == "True"
    MAIL_USERNAME = _env_str("MAIL_USERNAME", "")
    MAIL_PASSWORD = _env_str("MAIL_PASSWORD", "")


class DevelopmentConfig(BaseConfig):
    """Config pour le DEV local (HTTP clair, évite le reset)."""
    TALISMAN_FORCE_HTTPS = False
    TALISMAN_STRICT_TRANSPORT_SECURITY = False
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://unpkg.com", "https://cdn.jsdelivr.net", "https://js.stripe.com"],
        "style-src": ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'", "https://api.stripe.com"],
        "frame-ancestors": ["'none'"],
        "frame-src": ["'self'", "https://js.stripe.com", "https://checkout.stripe.com"],
    }


class ProductionConfig(BaseConfig):
    """Config production (HTTPS forcé)."""
    TALISMAN_FORCE_HTTPS = True
    TALISMAN_STRICT_TRANSPORT_SECURITY = True  # HSTS actif
    # Renforts d’en-têtes
    TALISMAN_STRICT_TRANSPORT_SECURITY_PRELOAD = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_INCLUDE_SUBDOMAINS = True
    TALISMAN_REFERRER_POLICY = "strict-origin-when-cross-origin"
    TALISMAN_PERMISSIONS_POLICY = {
        "geolocation": "()",
        "camera": "()",
        "microphone": "()",
        "payment": "()",
        "fullscreen": "()",
    }
    TALISMAN_CONTENT_SECURITY_POLICY = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://unpkg.com", "https://cdn.jsdelivr.net", "https://js.stripe.com"],
        "style-src": ["'self'", "https://cdn.jsdelivr.net"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'", "https://api.stripe.com"],
        "frame-ancestors": ["'none'"],
        "frame-src": ["'self'", "https://js.stripe.com", "https://checkout.stripe.com"],
        "font-src": ["'self'", "data:"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'", "https://checkout.stripe.com"],
    }

    # Cookies vraiment secure en prod
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Lax"  # Lax = bon compromis avec des flux externes (Checkout/OAuth)


# === Sélecteur de config par variable d'env (optionnel) ===
CONFIG_NAME = _env_str("APP_CONFIG", "development").lower()
Config = DevelopmentConfig if CONFIG_NAME.startswith("dev") else ProductionConfig
