# Rapport d'auto-audit – secure-file-app

### AES-GCM (PyCryptodome)
✅  
- app\utils\encryption_utils.py
### Nonce 12 octets / tag vérifié
✅  
- app\routes\auth_routes.py
- app\utils\encryption_utils.py
- app\utils\signature_utils.py
### KDF (Argon2/PBKDF2)
✅  
- auto_audit.py
### RSA 2048 + OAEP
✅  
- auto_audit.py
- generate_rsa_keys.py
- app\utils\encryption_utils.py
- app\utils\keygen.py
### Signature PSS
✅  
- auto_audit.py
### PyOTP (TOTP)
✅  
- app\routes\auth_routes.py
### QR Code 2FA
✅  
- auto_audit.py
- app\routes\auth_routes.py
### Flask-Login / RBAC
✅  
- auto_audit.py
- app\extensions.py
- app\models\user.py
- app\routes\admin_routes.py
- app\routes\auth_routes.py
- app\routes\main_routes.py
- app\utils\decorators.py
### CSRF Protect
✅  
- app\extensions.py
### Flask-Limiter (bruteforce)
✅  
- app\extensions.py
- app\routes\auth_routes.py
### Cookies sécurisés
✅  
- auto_audit.py
### Stripe (server-side)
❌  
- (aucune occurrence trouvée)
### Stripe webhooks + vérif signature
❌  
- (aucune occurrence trouvée)
### Lien paiement → téléchargement (URLs signées)
✅  
- auto_audit.py
### Validation fichier (MIME/magic)
✅  
- auto_audit.py
- app\routes\main_routes.py
### Sanitisation noms de fichier
✅  
- auto_audit.py
- app\routes\main_routes.py
### CSP headers
✅  
- auto_audit.py
### Docker non-root user
✅  
- auto_audit.py
- create_admin.py
- seed_admin.py
- suppr.py
- app\__init__.py
- app\models\__init__.py
- app\routes\admin_routes.py
- app\routes\auth_routes.py
- app\routes\main_routes.py
- app\templates\admin_panel.html
- app\utils\decorators.py
- migrations\versions\79bc0a852f2a_initial_migration_create_user_model.py
### Pinned deps (requirements/pyproject)
✅  
- auto_audit.py
- generate_rsa_keys.py
- run.py
- app\models\user.py
- app\routes\admin_routes.py
- app\routes\main_routes.py
- app\templates\base.html
- app\templates\home.html
- app\templates\upload.html
- app\templates\partials\flash_messages.html
### Tests pytest
❌  
- (aucune occurrence trouvée)
### Load tests (Locust/Artillery)
✅  
- auto_audit.py
### GitHub Actions
✅  
- auto_audit.py
### Logs structurés JSON
✅  
- app\routes\main_routes.py
- app\utils\logging_config.py
- migrations\env.py
