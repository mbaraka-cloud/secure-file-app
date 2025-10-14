# app/utils/billing.py
import math
from typing import Iterable, Tuple, Optional
from sqlalchemy import text
from app.extensions import db


def credits_cost_for_bytes(
    total_bytes: int,
    palier_mo: int,
    session_fee: int,
) -> int:
    """
    Formule "Option A":
      crédits = session_fee + floor(total_Mo / palier_mo)
    - total_bytes: taille totale en octets
    - palier_mo : ex. 500
    - session_fee: ex. 1
    """
    if total_bytes <= 0:
        return 0
    total_mo = total_bytes / (1024 * 1024)
    return int(session_fee + math.floor(total_mo / float(palier_mo)))


def _detect_encrypted_file_size_column() -> str:
    """
    Détecte la colonne de taille dans la table encrypted_file.
    Essaie size_bytes, puis size, puis filesize.
    """
    cols = []
    try:
        res = db.session.execute(text("PRAGMA table_info(encrypted_file)"))
        cols = [row[1] for row in res.fetchall()]
    except Exception:
        pass
    for c in ("size_bytes", "size", "filesize"):
        if c in cols:
            return c
    # fallback conservateur
    return "size"  # si ça n'existe pas, l'appel SQL lèvera une erreur explicite


def sum_bytes_for_file_ids(file_ids: Iterable[int]) -> int:
    """
    Additionne les tailles des fichiers par IDs depuis la table encrypted_file.
    Sécure (bind params) et compatible SQLite.
    """
    ids = []
    for i in file_ids:
        s = str(i)
        if s.isdigit():
            ids.append(int(s))
    if not ids:
        return 0

    col = _detect_encrypted_file_size_column()
    placeholders = ",".join([f":id{i}" for i in range(len(ids))])
    params = {f"id{i}": ids[i] for i in range(len(ids))}
    sql = text(f"SELECT COALESCE(SUM({col}), 0) AS total FROM encrypted_file WHERE id IN ({placeholders})")
    row = db.session.execute(sql, params).first()
    return int(row[0] or 0)


def estimate_for_ids(
    file_ids: Iterable[int],
    palier_mo: int,
    session_fee: int,
    bytes_override: Optional[int] = None,
) -> Tuple[int, int]:
    """
    Retourne (total_bytes, credits).
    - Si bytes_override est fourni, l'utilise.
    - Sinon, somme depuis la DB via encrypted_file.
    """
    total_bytes = int(bytes_override) if (bytes_override is not None) else sum_bytes_for_file_ids(file_ids)
    credits = credits_cost_for_bytes(total_bytes, palier_mo=palier_mo, session_fee=session_fee)
    return total_bytes, credits
