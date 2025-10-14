from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length


class RegisterForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur",
        validators=[DataRequired(), Length(min=3, max=25)]
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        "Mot de passe",
        validators=[DataRequired(), Length(min=6)]
    )
    submit = SubmitField("Créer un compte")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        "Mot de passe",
        validators=[DataRequired()]
    )
    submit = SubmitField("Se connecter")


class TwoFactorCodeForm(FlaskForm):
    token = StringField(
        "Code TOTP",
        validators=[DataRequired(), Length(min=6, max=6)]
    )
    submit = SubmitField("Valider le code")


class Enable2FAForm(FlaskForm):
    submit = SubmitField("Activer la double authentification")


class DummyForm(FlaskForm):
    """
    Formulaire vide uniquement utilisé pour générer un token CSRF
    dans les modals ou actions HTMX.
    """
    submit = SubmitField("Confirmer")
