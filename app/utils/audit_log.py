# app/utils/audit_log.py
from app.extensions import db
from app.models.billing_event import BillingEvent

def log_account_deletion(user_id: int, meta: dict | None = None):
    """
    Écrit un événement d’audit pour la suppression de compte utilisateur.
    """
    ev = BillingEvent(
        user_id=user_id,
        kind="account_delete",        # visible dans /admin/audit (onglet "billing" ou "all")
        credits_cost=0,
        credits_delta=0,
        label="User self-delete",
        meta_json=(meta or None),
        bytes_total=0
    )
    db.session.add(ev)
