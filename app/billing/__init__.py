from flask import Blueprint

billing_bp = Blueprint(
    "billing",
    __name__,
    template_folder="../templates/billing",
    static_folder="../static",
)

# Importer les routes pour enregistrer les endpoints
from . import routes  # noqa: E402,F401
