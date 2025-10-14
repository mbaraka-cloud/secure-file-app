# app/models/encrypted_file.py
from app.extensions import db

class EncryptedFile(db.Model):
    __tablename__ = "encrypted_file"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False, index=True)
    content_type = db.Column(db.String(255), nullable=False)

    # 🔐 Données chiffrées
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    tag = db.Column(db.LargeBinary, nullable=False)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)

    # 👤 Propriétaire
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    # 🆕 Catégorie (Document, Image, Audio, Vidéo, Logiciel, Archive, Autre)
    category = db.Column(db.String(20), nullable=False, default="Autre", index=True)

    # Si tu as déjà un timestamp, garde-le. Sinon, tu peux ajouter :
    # created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False, index=True)

    owner = db.relationship("User", backref=db.backref("files", lazy=True))

    def __repr__(self) -> str:
        return f"<EncryptedFile id={self.id} filename={self.filename!r} category={self.category!r}>"
