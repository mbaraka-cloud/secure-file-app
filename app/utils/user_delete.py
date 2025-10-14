# app/utils/user_delete.py
from sqlalchemy import text
from app.extensions import db
from app.models.user import User
from app.models.encrypted_file import EncryptedFile
from app.models.file_share import FileShare
from app.models.credit_usage import CreditUsage
from app.models.purchase import Purchase
from app.models.billing_event import BillingEvent  # ← IMPORTANT: audit

def delete_user_cascade(user: User) -> None:
    """
    Supprime proprement un utilisateur et toutes ses données liées.
    NE FAIT PAS de commit : c'est au caller de commit/rollback.
    Ordre choisi pour éviter toute violation de FK.
    """

    # 1) Données d'audit/usage/achats (référencent user_id)
    BillingEvent.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    CreditUsage.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    Purchase.query.filter_by(user_id=user.id).delete(synchronize_session=False)

    # 2) Partages (proprio + destinataire)
    FileShare.query.filter_by(owner_id=user.id).delete(synchronize_session=False)
    FileShare.query.filter_by(shared_with_user_id=user.id).delete(synchronize_session=False)

    # 3) Anciennes tables de tokens (compat)
    try:
        db.session.execute(text("DELETE FROM download_token  WHERE user_id = :uid"), {"uid": user.id})
    except Exception:
        pass
    try:
        db.session.execute(text("DELETE FROM download_tokens WHERE user_id = :uid"), {"uid": user.id})
    except Exception:
        pass

    # 4) Fichiers chiffrés (FK vers user_id)
    for f in EncryptedFile.query.filter_by(user_id=user.id).all():
        db.session.delete(f)

    # 5) Enfin, l'utilisateur
    db.session.delete(user)
