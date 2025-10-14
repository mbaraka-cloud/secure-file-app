# app/models/credit_usage.py
from datetime import datetime
from app.extensions import db

class CreditUsage(db.Model):
    __tablename__ = "credit_usage"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # "download" pour un lot de téléchargement
    kind = db.Column(db.String(32), nullable=False, default="download")

    bytes_total = db.Column(db.Integer, nullable=False, default=0)
    credits_cost = db.Column(db.Integer, nullable=False, default=0)

    # JSON texte libre (ids de fichiers, share_id, notes…)
    meta_json = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
