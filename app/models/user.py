from app.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import time
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = "user"  # important pour correspondre aux FKs existants

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' | 'admin'
    credits = db.Column(db.Integer, nullable=False, default=0)

    # Profil (ajouts optionnels)
    first_name = db.Column(db.String(80), nullable=True)
    last_name  = db.Column(db.String(80), nullable=True)
    phone      = db.Column(db.String(40), nullable=True)

    # Consentements
    privacy_accepted_at = db.Column(db.DateTime, nullable=True)  # horodatage d'acceptation

    # Authentification 2FA
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(64), nullable=True)

    # Protection brute force
    failed_attempts = db.Column(db.Integer, default=0)
    banned_until = db.Column(db.Integer, default=0)  # Timestamp UNIX (secondes)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # --- Helpers ---
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == 'admin'

    def is_banned(self) -> bool:
        return time.time() < (self.banned_until or 0)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
