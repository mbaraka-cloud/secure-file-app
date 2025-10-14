from datetime import datetime, timedelta
import secrets

from app.extensions import db  # <-- adapte si besoin (ex: from yourapp.extensions import db)


class Wallet(db.Model):
    __tablename__ = "wallets"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, unique=True, nullable=False)
    balance_credits = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class CreditTransaction(db.Model):
    __tablename__ = "credit_transactions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    change = db.Column(db.Integer, nullable=False)  # +topup, -debit
    reason = db.Column(db.String(64), nullable=False)  # 'topup'|'debit_download'|'refund'
    reference = db.Column(db.String(128), nullable=True)  # ex: payment_intent ou lot_id
    meta_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class PaymentSession(db.Model):
    __tablename__ = "payment_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    stripe_session_id = db.Column(db.String(128), unique=True, nullable=False)
    stripe_payment_intent = db.Column(db.String(128), index=True, nullable=True)
    amount = db.Column(db.Integer, nullable=False)     # en cents (ou ariary si tu comptes en MGA)
    currency = db.Column(db.String(8), nullable=False, default="eur")
    credits_purchased = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(16), nullable=False, default="pending")  # pending|paid|failed
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class DownloadLot(db.Model):
    __tablename__ = "download_lots"
    id = db.Column(db.Integer, primary_key=True)
    recipient_user_id = db.Column(db.Integer, index=True, nullable=False)
    share_id = db.Column(db.Integer, index=True, nullable=True)  # si tu as une table Share
    total_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    cost_credits = db.Column(db.Integer, nullable=False, default=0)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(24)

    @classmethod
    def create_with_expiry(cls, recipient_user_id: int, total_bytes: int, cost_credits: int, minutes_valid: int, share_id=None):
        expires_at = datetime.utcnow() + timedelta(minutes=minutes_valid)
        token = cls.generate_token()
        return cls(
            recipient_user_id=recipient_user_id,
            share_id=share_id,
            total_bytes=total_bytes,
            cost_credits=cost_credits,
            token=token,
            expires_at=expires_at,
        )
