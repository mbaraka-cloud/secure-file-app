from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Dictionnaire pour stocker les clés associées aux fichiers
file_keys = {}

# Fonction pour générer une clé AES
def generate_key():
    return get_random_bytes(16)  # 16 bytes pour AES-128

# Fonction pour stocker une clé pour un fichier spécifique
def store_key(file_name, key):
    file_keys[file_name] = key

# Fonction pour chiffrer un fichier
def encrypt_file(file_path, file_name):
    key = generate_key()  # Générer une nouvelle clé pour ce fichier
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_file_path = file_path + ".enc"
    
    # Enregistrer le fichier chiffré
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher.iv)  # Ajouter le vecteur d'initialisation (IV)
        f.write(ciphertext)
    
    # Stocker la clé
    store_key(file_name, key)
    os.remove(file_path)  # Supprimer le fichier original après chiffrement
    return encrypted_file_path

# Fonction pour déchiffrer un fichier
def decrypt_file(encrypted_file_path, file_name):
    # Récupérer la clé associée au fichier
    key = file_keys.get(file_name)
    if not key:
        raise ValueError("Clé de fichier introuvable.")
    
    # Ouvrir le fichier chiffré
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)  # Lire le vecteur d'initialisation (IV) qui fait 16 octets
        ciphertext = f.read()  # Lire le texte chiffré

    # Créer un objet de chiffrement avec la clé et le IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Déchiffrer le texte
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Sauvegarder le fichier déchiffré
    decrypted_file_path = encrypted_file_path.replace('.enc', '_decrypted')
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)
    
    return decrypted_file_path
