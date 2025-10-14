# app/models/download_token.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy.sql import func

from app.extensions import db

# S'aligne sur ton schéma actuel : tables 'user' et 'encrypted_file'
try:
    from app.models.user import User as _User
    _USER_TABLE = getattr(_User, "__tablename__", "user")
except Exception:
    _USER_TABLE = "user"

try:
    from app.models.encrypted_file import EncryptedFile as _EF
    _ENC_TABLE = getattr(_EF, "__tablename__", "encrypted_file")
except Exception:
    _ENC_TABLE = "encrypted_file"


class DownloadToken(db.Model):
    __tablename__ = "download_token"  # conserve le nom existant si déjà créé

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, index=True, nullable=False)

    file_id = db.Column(db.Integer, db.ForeignKey(f"{_ENC_TABLE}.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey(f"{_USER_TABLE}.id", ondelete="CASCADE"), nullable=False, index=True)

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def is_used(self) -> bool:
        return self.used_at is not None

    def is_expired(self, ttl_minutes: int) -> bool:
        if not self.created_at:
            return True
        try:
            now = datetime.now(timezone.utc)
            return self.created_at + timedelta(minutes=int(ttl_minutes or 0)) < now
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"<DownloadToken id={self.id} user={self.user_id} file={self.file_id} used={self.used_at is not None}>"
