# magic shim: fournit une classe Magic compatible minimale
# pour éviter d'installer python-magic en dev sous Windows.

import mimetypes


class Magic:
    def __init__(self, mime=False, *_, **__):
        self.mime = mime

    def from_file(self, path):
        mt, _ = mimetypes.guess_type(path)
        return mt or "application/octet-stream"

    def from_buffer(self, buf):
        # heuristique très simple (JPEG/PNG/PDF/ZIP), sinon mimetype par défaut
        if isinstance(buf, (bytes, bytearray)):
            head = bytes(buf[:8])
            if head.startswith(b"\xFF\xD8\xFF"):
                return "image/jpeg"
            if head.startswith(b"\x89PNG\r\n\x1a\n"):
                return "image/png"
            if head.startswith(b"%PDF"):
                return "application/pdf"
            if head.startswith(b"PK\x03\x04"):
                return "application/zip"
        return "application/octet-stream"
