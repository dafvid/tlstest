from flask import Flask, render_template, request
from flask_json import FlaskJSON, as_json

from .forms import HostForm, SmimeaForm, FetchSmimeaForm
from .. import make_https_result, make_smimea, make_smtp_result, \
    make_sshfp_result, make_fetch_smimea, util

app = Flask(__name__)
app.secret_key = "123456789"

json = FlaskJSON(app)
app.config['JSON_DATETIME_FORMAT'] = "%Y-%m-%d %H:%M:%S"
app.config['SSLTEST_DEFAULT_HOST'] = ''


@app.route('/')
def main():
    return render_template('base.html')


@app.route('/api/https/<host>')
@app.route('/api/https/<host>/<int:port>')
@as_json
def api_https_port(host, port=443):
    return make_https_result(host, port)


@app.route('/api/smtp/<host>')
@app.route('/api/smtp/<host>/<int:port>')
@as_json
def api_smtp_port(host, port=25):
    return make_smtp_result(host, port)


@app.route('/api/sshfp/<host>')
@app.route('/api/sshfp/<host>/<int:port>')
@as_json
def api_sshfp_port(host, port=22):
    return make_sshfp_result(host, port)


@app.route('/https', methods=['GET', 'POST'])
def https():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = make_https_result(host, port)
    else:
        form.host.data = app.config['SSLTEST_DEFAULT_HOST']
        form.port.data = 443

    return render_template('https.html', form=form, result=result)


@app.route('/smtp', methods=['GET', 'POST'])
def smtp():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = make_smtp_result(host, port)
    else:
        form.host.data = ''
        form.host.data = app.config['SSLTEST_DEFAULT_HOST']
        form.port.data = 25

    return render_template('smtp.html', form=form, result=result)


@app.route('/sshfp', methods=['GET', 'POST'])
def sshfp():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = make_sshfp_result(host, port)

    else:
        form.host.data = ''
        form.host.data = app.config['SSLTEST_DEFAULT_HOST']
        form.port.data = 22

    return render_template('sshfp.html', form=form, result=result)


@app.route('/smimea', methods=['GET', 'POST'])
def smimea():
    form = SmimeaForm()
    fetch_form = FetchSmimeaForm(prefix='fetch_')
    r = None
    if form.validate_on_submit():
        r = {'type': 'make', 'result': make_smimea(form.mail.data, form.cert.data)}

    return render_template(
        'smimea.html',
        form=form,
        fetch_form=fetch_form,
        result=r)


@app.route('/fetch_smimea', methods=['POST'])
def fetch_smimea():
    form = SmimeaForm()
    fetch_form = FetchSmimeaForm(prefix='fetch_')
    r = None
    if fetch_form.validate_on_submit():
        r = {'type': 'fetch'}
        mail = fetch_form.mail.data

        try:
            r['data'] = make_fetch_smimea(mail)
        except util.TLSTestException as e:
            r['error'] = str(e)

    return render_template(
        'smimea.html',
        form=form,
        fetch_form=fetch_form,
        result=r)


@app.template_global()
def is_none(test):
    return test is None


@app.template_global()
def yn(test):
    return 'yes' if test else 'no'


@app.template_global()
def eq_yn(test, test2):
    return 'yes' if test == test2 else 'no'


@app.template_global()
def match_class(match):
    return 'green' if match == 'yes' else 'red'


@app.template_filter('df')
def df(d):
    return d.strftime('%Y-%m-%d')


@app.template_filter('join')
def join_filter(a):
    return ', '.join(a)
