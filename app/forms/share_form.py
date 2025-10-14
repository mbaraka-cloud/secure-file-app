# app/forms/share_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length

class ShareForm(FlaskForm):
    file_id = HiddenField("file_id", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired(), Email(), Length(max=150)])

class UnshareForm(FlaskForm):
    file_id = HiddenField("file_id", validators=[DataRequired()])
    user_id = HiddenField("user_id", validators=[DataRequired()])
