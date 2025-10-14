# app/utils/email_utils.py
"""
Envoi d'emails simple, sans dépendre d'un mailer tiers.
- Si les variables SMTP sont configurées dans current_app.config, on envoie via smtplib.
- Sinon, on logge proprement le contenu (fallback “DEBUG mailer”).
Config attendue (facultative) :
  MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS (bool), MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

def _cfg(key, default=None):
    return current_app.config.get(key, default)

def send_email(to: str, subject: str, html_body: str, text_body: str = None):
    sender = _cfg("MAIL_DEFAULT_SENDER") or _cfg("DEFAULT_MAIL_SENDER") or "no-reply@localhost"
    server = _cfg("MAIL_SERVER")
    port = int(_cfg("MAIL_PORT", 587))
    use_tls = bool(_cfg("MAIL_USE_TLS", True))
    username = _cfg("MAIL_USERNAME")
    password = _cfg("MAIL_PASSWORD")

    if not server:
        # Fallback : log ONLY (pas d’exception pour ne pas casser le flow)
        current_app.logger.warning(
            "[mailer:fallback] Aucun serveur SMTP configuré — email non envoyé.\n"
            f"TO: {to}\nSUBJECT: {subject}\nHTML:\n{html_body[:2000]}{'…' if len(html_body)>2000 else ''}"
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to

    if not text_body:
        # texte minimal fallback
        text_body = "Veuillez ouvrir cet email dans un client compatible HTML."
    part1 = MIMEText(text_body, "plain", "utf-8")
    part2 = MIMEText(html_body, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP(server, port) as smtp:
            if use_tls:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(sender, [to], msg.as_string())
        current_app.logger.info(f"[mailer] Email envoyé à {to} (subject={subject})")
    except Exception:
        current_app.logger.exception("[mailer] Echec d'envoi SMTP")
