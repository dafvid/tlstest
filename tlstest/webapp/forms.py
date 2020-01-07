from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, TextAreaField, validators


class SmimeaForm(FlaskForm):
    mail = StringField('E-mail', [validators.required(), validators.Email()])
    cert = TextAreaField('Certificate', [validators.required()])


class FetchSmimeaForm(FlaskForm):
    mail = StringField('E-mail', [validators.required(), validators.Email()])


class HostForm(FlaskForm):
    host = StringField('Host', [validators.required()])
    port = IntegerField('Port', [validators.required()])
