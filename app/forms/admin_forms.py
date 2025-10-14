# app/forms/admin_forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length

class AdminCreateUserForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField("Mot de passe", validators=[DataRequired(), Length(min=6, max=128)])
    role = SelectField(
        "Rôle",
        choices=[("user", "Utilisateur"), ("admin", "Administrateur")],
        validators=[DataRequired()]
    )
