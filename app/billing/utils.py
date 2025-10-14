from math import floor
from flask import current_app

def bytes_to_megabytes(n_bytes: int) -> int:
    return int(round(n_bytes / (1024.0 * 1024.0)))

def estimate_credits_for_lot(total_bytes: int) -> int:
    """
    Option A (recommandée) :
      crédits = SESSION_FEE + floor(total_Mo / PALIER_MO)

    Config attendue dans app.config :
      BILLING_CREDIT_PALIER_MO (defaut 500)
      BILLING_SESSION_FEE_CREDITS (defaut 1)
    """
    total_mo = bytes_to_megabytes(total_bytes)
    palier_mo = int(current_app.config.get("BILLING_CREDIT_PALIER_MO", 500))
    session_fee = int(current_app.config.get("BILLING_SESSION_FEE_CREDITS", 1))
    return session_fee + floor(max(0, total_mo) / palier_mo)
