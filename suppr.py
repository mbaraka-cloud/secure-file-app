from app import create_app
from app.models.user import User, db

app = create_app()
with app.app_context():
    user = User.query.filter_by(email="admin@example.com").first()  # ← modifie avec ton vrai email
    if user:
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.session.commit()
        print("2FA désactivée avec succès pour l'utilisateur :", user.email)
    else:
        print("Utilisateur non trouvé.")
