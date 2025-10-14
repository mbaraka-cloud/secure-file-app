# app/utils/zip_utils.py
from datetime import datetime
from typing import Iterable, Callable
from werkzeug.utils import secure_filename
import zipfile
import tempfile

def build_zip_file(files: Iterable, decrypt_fn: Callable) -> tuple[object, str]:
    """
    Construit un ZIP en mode spool (évite d'exploser la RAM).
    - files: itérable d'objets ayant au moins .id et .filename
    - decrypt_fn: callable(f) -> bytes (plaintext du fichier)

    Retourne: (fp_like, download_name)
      * fp_like est un fichier-like (SpooledTemporaryFile) positionné à 0
      * download_name est un nom de fichier ZIP (str)
    """
    # 100 Mo de seuil en RAM avant de spouler sur disque (adapte si besoin)
    spooled = tempfile.SpooledTemporaryFile(max_size=100 * 1024 * 1024)

    with zipfile.ZipFile(spooled, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            try:
                plaintext = decrypt_fn(f)
                # Nom d'entrée sûr
                name = secure_filename(getattr(f, "filename", "") or f"file_{getattr(f, 'id', 'unknown')}")
                if not name:
                    name = f"file_{getattr(f, 'id', 'unknown')}"
                zf.writestr(name, plaintext)
            except Exception as e:
                err_name = f"ERROR_{getattr(f, 'id', 'unknown')}.txt"
                zf.writestr(err_name, f"Erreur de déchiffrement: {str(e)}")

    spooled.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    zip_name = f"export_{ts}.zip"
    return spooled, zip_name
