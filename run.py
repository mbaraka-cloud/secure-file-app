# run.py
import os
import sys
from dotenv import load_dotenv

# Charge .env au tout début
load_dotenv()

from app import create_app

def main():
    app = create_app()

    # Lecture des paramètres d'exécution
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = True  # dev
    use_ssl = os.environ.get("USE_SSL", "false").lower() in ("1", "true", "yes")

    # Petits logs de contrôle
    print(f"[run.py] Dev {'HTTPS' if use_ssl else 'HTTP'} on http://{host}:{port}")
    # (NB: l'URL est affichée en http pour cliquer facilement; si USE_SSL=true, tu sauras que c'est HTTPS)

    # Lancement Flask
    if use_ssl:
        # En dev, déconseillé (certificat self-signed). Gardé pour compatibilité.
        # Fournis tes chemins cert/key si tu veux forcer le HTTPS localement :
        ssl_context = ("cert.pem", "key.pem") if os.path.exists("cert.pem") and os.path.exists("key.pem") else "adhoc"
        app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
    else:
        app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[run.py] Fatal error:", e, file=sys.stderr)
        raise
