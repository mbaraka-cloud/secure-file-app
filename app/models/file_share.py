# app/models/file_share.py
from datetime import datetime
from app.extensions import db

class FileShare(db.Model):
    __tablename__ = "file_share"

    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(db.Integer, db.ForeignKey("encrypted_file.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("file_id", "shared_with_user_id", name="uq_file_share_file_user"),
    )
