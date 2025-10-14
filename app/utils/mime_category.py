# app/utils/mime_category.py
import os

DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt",
    ".xls", ".xlsx", ".ods", ".csv",
    ".ppt", ".pptx", ".odp",
    ".md", ".epub",
}
ARCHIVE_EXTS  = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
SOFTWARE_EXTS = {".exe", ".msi", ".apk", ".dmg", ".pkg", ".appimage", ".deb", ".rpm"}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg"}
AUDIO_EXTS = {".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus", ".wma", ".aif", ".aiff"}
VIDEO_EXTS = {".mp4", ".m4v", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".mpg", ".mpeg", ".3gp", ".3gpp", ".3g2"}

def _ext(path: str) -> str:
    return os.path.splitext(path or "")[1].lower()

def categorize_mime(content_type: str, filename: str | None = None) -> str:
    """
    Retourne une catégorie lisible à partir d'un mimetype (et du nom de fichier en secours).
    Catégories : Document, Image, Audio, Vidéo, Logiciel, Archive, Autre
    """
    ct = (content_type or "").lower()
    ext = _ext(filename or "")

    # Forts signaux via mimetype
    if ct.startswith("image/"):
        return "Image"
    if ct.startswith("audio/"):
        return "Audio"
    if ct.startswith("video/"):
        return "Vidéo"
    if ct in {
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain", "text/markdown",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/epub+zip",
    }:
        return "Document"
    if ct in {"application/x-msdownload", "application/x-executable",
              "application/vnd.android.package-archive"}:
        return "Logiciel"
    if ct in {"application/zip", "application/x-7z-compressed",
              "application/x-rar-compressed", "application/x-tar",
              "application/gzip", "application/x-bzip2", "application/x-xz"}:
        return "Archive"

    # Secours via extension si mimetype ambigu/inconnu
    if ext in IMAGE_EXTS:
        return "Image"
    if ext in AUDIO_EXTS:
        return "Audio"
    if ext in VIDEO_EXTS:
        return "Vidéo"
    if ext in DOCUMENT_EXTS:
        return "Document"
    if ext in ARCHIVE_EXTS:
        return "Archive"
    if ext in SOFTWARE_EXTS:
        return "Logiciel"

    return "Autre"
