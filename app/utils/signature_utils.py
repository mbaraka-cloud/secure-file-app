from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_data(data: bytes, private_key):
    """Renvoie la signature RSA du contenu en utilisant la clé privée."""
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, public_key):
    """Vérifie qu’une signature correspond au contenu, en utilisant la clé publique."""
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False