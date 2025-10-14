from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_talisman import Talisman

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Limiter : aucune limite globale (limites définies route par route)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
)

migrate = Migrate()
talisman = Talisman()


@login_manager.user_loader
def load_user(user_id):
    from .models.user import User
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

login_manager.login_view = "auth.login"
