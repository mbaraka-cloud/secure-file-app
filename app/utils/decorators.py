# app/utils/decorators.py
from functools import wraps
from flask import abort
from flask_login import current_user

def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Compat : is_admin peut être bool OU méthode
        is_admin_attr = getattr(current_user, "is_admin", False)
        try:
            is_admin_flag = bool(is_admin_attr()) if callable(is_admin_attr) else bool(is_admin_attr)
        except Exception:
            is_admin_flag = False
        if not is_admin_flag:
            return abort(403)
        return view(*args, **kwargs)
    return wrapper
