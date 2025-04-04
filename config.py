import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///secure_file_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    # Augmentation des limites globales
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5 Go maximum (doit couvrir votre plus gros fichier)
    # Configuration des cookies pour la session
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
