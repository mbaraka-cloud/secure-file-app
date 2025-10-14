# app/utils/urls.py
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app

_SALT = "download-token"

def _serializer():
    secret = current_app.config["SECRET_KEY"]
    return URLSafeTimedSerializer(secret_key=secret, salt=_SALT)

def sign_download_token(file_id: int, user_id: int) -> str:
    s = _serializer()
    return s.dumps({"f": file_id, "u": user_id})

def verify_download_token(token: str) -> dict:
    s = _serializer()
    max_age = int(current_app.config.get("DOWNLOAD_TOKEN_EXP_SECONDS", 900))
    try:
        data = s.loads(token, max_age=max_age)
        # attendu: {"f": <file_id>, "u": <user_id>}
        if not isinstance(data, dict) or "f" not in data or "u" not in data:
            raise BadSignature("payload invalide")
        return data
    except SignatureExpired as e:
        raise e
    except BadSignature as e:
        raise e
