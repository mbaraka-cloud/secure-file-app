# auto_audit.py
import os, re, json, sys, hashlib
from pathlib import Path

ROOT = Path(".")
REPORT = []

def list_files():
    exts = (".py",".js",".ts",".html",".htmx",".jinja2",".j2",".json",".yml",".yaml",".toml",".env",".md",".css",".dockerfile","Dockerfile")
    files = []
    for p in ROOT.rglob("*"):
        if p.is_file() and (p.suffix.lower() in exts or p.name in ("Dockerfile",".env",".env.example","requirements.txt","pyproject.toml","package.json","Procfile")):
            files.append(p)
    return files

def grep(patterns, text):
    return any(re.search(p, text, re.I|re.M) for p in patterns)

def check(name, patterns, files):
    hits = []
    for f in files:
        try:
            t = f.read_text(errors="ignore")
        except:
            continue
        if grep(patterns, t):
            hits.append(str(f))
    status = "✅" if hits else "❌"
    REPORT.append(f"### {name}\n{status}  \n" + ("\n".join(f"- {h}" for h in hits) or "- (aucune occurrence trouvée)") + "\n")

files = list_files()

checks = [
    ("AES-GCM (PyCryptodome)", [r"AES\.MODE_GCM", r"from\s+Crypto\.Cipher\s+import\s+AES"]),
    ("Nonce 12 octets / tag vérifié", [r"nonce\s*=\s*.{0,30}(12|b'\x00{12}')", r"verify\("]),
    ("KDF (Argon2/PBKDF2)", [r"argon2", r"PBKDF2"]),
    ("RSA 2048 + OAEP", [r"RSA\.generate\(\s*2048", r"PKCS1_OAEP|OAEP"]),
    ("Signature PSS", [r"PKCS1_PSS|PSS"]),
    ("PyOTP (TOTP)", [r"import\s+pyotp", r"pyotp\.TOTP"]),
    ("QR Code 2FA", [r"qrcode", r"otpauth://"]),
    ("Flask-Login / RBAC", [r"from\s+flask_login\s+import", r"@login_required", r"roles?_required"]),
    ("CSRF Protect", [r"from\s+flask_wtf\s+import\s+CSRFProtect", r"CSRFProtect\("]),
    ("Flask-Limiter (bruteforce)", [r"from\s+flask_limiter\s+import", r"@limiter\.limit"]),
    ("Cookies sécurisés", [r"SESSION_COOKIE_SECURE\s*=\s*True", r"SESSION_COOKIE_HTTPONLY\s*=\s*True", r"SAMESITE"]),
    ("Stripe (server-side)", [r"import\s+stripe", r"stripe\.(Checkout|PaymentIntent)"]),
    ("Stripe webhooks + vérif signature", [r"request\.headers\.get\(['\"]Stripe-Signature", r"stripe\.Webhook"]),
    ("Lien paiement → téléchargement (URLs signées)", [r"itsdangerous|URLSafeSerializer|signer|presign"]),
    ("Validation fichier (MIME/magic)", [r"python-magic|filetype|mimetypes", r"secure_filename"]),
    ("Sanitisation noms de fichier", [r"secure_filename"]),
    ("CSP headers", [r"Content-Security-Policy", r"resp\.headers\['Content-Security-Policy'\]"]),
    ("Docker non-root user", [r"USER\s+\w+", r"adduser", r"useradd"]),
    ("Pinned deps (requirements/pyproject)", [r"==\d", r"~=|=="]),
    ("Tests pytest", [r"import\s+pytest", r"def\s+test_"]),
    ("Load tests (Locust/Artillery)", [r"from\s+locust\s+import", r"artillery"]),
    ("GitHub Actions", [r"on:\s*(push|pull_request)", r"jobs:"]),
    ("Logs structurés JSON", [r"json\.dumps\(", r"logging\.getLogger"]),
]

for name, pats in checks:
    check(name, pats, files)

# --- à la place du print final ---
def write_report(path="audit_report.md"):
    content = ["# Rapport d'auto-audit – secure-file-app\n\n"]
    content.extend(REPORT)
    text = "".join(content)
    # On écrit directement en UTF-8, sans dépendre de l'encodage de la console
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

if __name__ == "__main__":
    write_report()
    # Message console en ASCII seulement (pour éviter toute erreur d'encodage)
    print("OK: audit_report.md ecrit en UTF-8")
