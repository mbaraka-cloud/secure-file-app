from Crypto.PublicKey import RSA
import os

# 📁 Dossier où seront stockées les clés
KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "rsa_private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "rsa_public.pem")

def generate_keys():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    key = RSA.generate(2048)  # 🔑 Taille de clé : 2048 bits

    # ✍️ Sauvegarde de la clé privée
    private_key = key.export_key()
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key)

    # ✍️ Sauvegarde de la clé publique
    public_key = key.publickey().export_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key)

    print("✅ Clés RSA générées dans le dossier 'keys/'")

if __name__ == "__main__":
    generate_keys()
