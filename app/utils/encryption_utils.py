# app/utils/encryption_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from flask import current_app

def _get_paths():
    pub = current_app.config.get("RSA_PUBLIC_KEY_PATH")
    priv = current_app.config.get("RSA_PRIVATE_KEY_PATH")
    if not pub or not priv:
        raise RuntimeError("RSA key paths not configured")
    return pub, priv

def encrypt_file_hybrid(file_data: bytes):
    # Génération de la clé AES et du nonce (GCM)
    aes_key = get_random_bytes(32)  # AES-256
    nonce = get_random_bytes(12)    # GCM nonce standard (12 bytes)

    # Chiffrement AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Chiffrement de la clé AES avec RSA-OAEP
    public_path, _ = _get_paths()
    with open(public_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    return {
        "ciphertext": ciphertext,
        "encrypted_key": encrypted_key,
        "nonce": nonce,
        "tag": tag
    }

def decrypt_file_hybrid(ciphertext: bytes, encrypted_key: bytes, nonce: bytes, tag: bytes) -> bytes:
    # Déchiffrement de la clé AES
    _, private_path = _get_paths()
    with open(private_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)

    # Déchiffrement AES-GCM avec vérification du tag
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext
