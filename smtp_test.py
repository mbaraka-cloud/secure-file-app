import smtplib

smtp_server = "smtp.gmail.com"
smtp_port = 465
username = "tsarafarah@gmail.com"
password = "edsnulysjgaurtwx"  # Remplace par ton mot de passe d'application sans espaces

try:
    # Utilise SMTP_SSL pour une connexion sécurisée
    server = smtplib.SMTP_SSL(smtp_server, smtp_port)
    server.login(username, password)
    print("Connexion SMTP réussie !")
    server.quit()
except Exception as e:
    print("Erreur SMTP :", e)
