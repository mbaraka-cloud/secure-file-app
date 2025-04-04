from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    country = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    mobile_number = db.Column(db.String(20), nullable=True)  # Nouveau champ pour le numéro de mobile
    security_question = db.Column(db.String(256), nullable=True)  # Question de sécurité
    security_answer_hash = db.Column(db.String(256), nullable=True)  # Réponse hachée à la question de sécurité
    files = db.relationship('File', backref='uploader', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_reset_token(self, expires_sec=1800):
        from itsdangerous import URLSafeTimedSerializer as Serializer
        from flask import current_app
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='password-reset')
    
    @staticmethod
    def verify_reset_token(token):
        from itsdangerous import URLSafeTimedSerializer as Serializer
        from flask import current_app
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='password-reset')['user_id']
        except Exception:
            return None
        return User.query.get(user_id)
    
    def promote_to_admin(self):
        self.is_admin = True
        db.session.commit()
    
    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(200), nullable=False)
    stored_filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f'<File {self.original_filename} ({self.category})>'
