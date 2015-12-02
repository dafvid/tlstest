import flask_wtf as fwtf
from wtforms import *


class HostForm(fwtf.Form):
    host = StringField('Host', [validators.required()])
    port = IntegerField('Port', [validators.required()])
