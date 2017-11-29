from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, validators, TextAreaField


class SmimeaForm(FlaskForm):
    mail = StringField('E-mail', [validators.required(), validators.Email()])
    cert = TextAreaField('Certificate')


class HostForm(FlaskForm):
    host = StringField('Host', [validators.required()])
    port = IntegerField('Port', [validators.required()])