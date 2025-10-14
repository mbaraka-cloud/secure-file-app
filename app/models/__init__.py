# app/models/__init__.py
# Charger TOUTES les classes de modèle ici pour qu'Alembic "voit" bien les tables
# lors de l'autogénération des migrations.

from .user import User                                # noqa
from .encrypted_file import EncryptedFile             # noqa
from .file_share import FileShare                     # noqa

# Ces modèles peuvent ne pas exister dans toutes les branches → importer prudemment
try:
    from .download_token import DownloadToken         # noqa
except Exception:
    pass

try:
    from .purchase import Purchase                    # noqa
except Exception:
    pass

try:
    from .credit_usage import CreditUsage             # noqa
except Exception:
    pass

try:
    from .billing_event import BillingEvent           # noqa
except Exception:
    pass
