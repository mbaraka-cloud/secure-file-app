# app/models/billing_event.py
from app.extensions import db
from sqlalchemy.sql import func

# --- Résolution dynamique du nom de table de User ---
try:
    from app.models.user import User as _User
    _USER_TABLE = getattr(_User, "__tablename__", "users")
except Exception:
    _USER_TABLE = "users"


class BillingEvent(db.Model):
    __tablename__ = "billing_events"

    id = db.Column(db.Integer, primary_key=True)

    # FK dynamique: "users.id" ou autre si ton modèle User change de nom
    user_id = db.Column(
        db.Integer,
        db.ForeignKey(f"{_USER_TABLE}.id"),
        nullable=False,
        index=True
    )

    # Champs "legacy" (on les garde)
    kind = db.Column(db.String(32), nullable=False, default="download")
    label = db.Column(db.String(64), nullable=True)
    file_ids_json = db.Column(db.Text, nullable=True)

    bytes_total = db.Column(db.Integer, nullable=False, default=0)
    credits_cost = db.Column(db.Integer, nullable=False, default=0)  # coût en crédits (débit)

    meta_json = db.Column(db.Text, nullable=True)

    # Optionnel : lecture/compat admin qui cherchait parfois 'credits_delta'
    # > Positif = crédit, Négatif = débit
    credits_delta = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self) -> str:
        return (
            f"<BillingEvent id={self.id} user={self.user_id} "
            f"kind={self.kind} label={self.label} credits_cost={self.credits_cost} delta={self.credits_delta}>"
        )
