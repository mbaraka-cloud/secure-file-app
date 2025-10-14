from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    username = "admin"
    email = "admin@example.com"
    password = "motdepassefort"
    role = "admin"

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"Utilisateur '{username}' déjà existant. Suppression en cours...")
        db.session.delete(existing_user)
        db.session.commit()

    admin = User(username=username, email=email, role=role)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"Nouvel utilisateur admin '{username}' créé avec succès ✅")
