from flask_wtf import FlaskForm
from wtforms import HiddenField

class DeleteForm(FlaskForm):
    file_id = HiddenField("file_id")
