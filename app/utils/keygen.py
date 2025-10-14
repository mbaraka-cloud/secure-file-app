from Crypto.PublicKey import RSA
import os

# Chemin du dossier où seront stockées les clés
key_dir = os.path.join(os.path.dirname(__file__), "../../keys")
os.makedirs(key_dir, exist_ok=True)

# Chemins complets des fichiers de clés
private_key_path = os.path.join(key_dir, "private.pem")
public_key_path = os.path.join(key_dir, "public.pem")

# Vérifie si les clés existent déjà
if os.path.exists(private_key_path) and os.path.exists(public_key_path):
    print("🔐 Les clés existent déjà.")
else:
    key = RSA.generate(2048)
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(key.export_key())

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    print("✅ Clés RSA générées avec succès.")
