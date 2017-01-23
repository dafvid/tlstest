from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, validators


class HostForm(FlaskForm):
    host = StringField('Host', [validators.required()])
    port = IntegerField('Port', [validators.required()])
