# app/routes/health.py
from flask import Blueprint, jsonify
from app.extensions import csrf, limiter

health_bp = Blueprint("health", __name__)

@health_bp.route("/healthz", methods=["GET"])
def healthz():
    # Retourne 200 plain & simple
    return jsonify(status="ok"), 200

# Exempter CSRF + rate limit (utile pour Docker/Nginx)
csrf.exempt(health_bp)
try:
    limiter.exempt(health_bp)
except Exception:
    pass
