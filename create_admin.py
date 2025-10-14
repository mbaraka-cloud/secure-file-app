from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app()

with app.app_context():
    admin = User(
        username="admin",
        email="admin@example.com",
        role="admin"
    )
    admin.set_password("Admin1234")  # 👈 mot de passe fort recommandé
    db.session.add(admin)
    db.session.commit()
    print("✅ Utilisateur admin créé avec succès.")
