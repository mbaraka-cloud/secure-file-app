# app/models/purchase.py
from datetime import datetime
from app.extensions import db

class Purchase(db.Model):
    __tablename__ = "purchase"

    id = db.Column(db.Integer, primary_key=True)
    # id de la session Stripe (unique pour empêcher le double-crédit)
    session_id = db.Column(db.String(128), unique=True, index=True, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Integer, nullable=False)   # en cents
    currency = db.Column(db.String(8), nullable=False)
    label = db.Column(db.String(64), nullable=True)

    # created | paid | credited | failed
    status = db.Column(db.String(32), default="created", nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
