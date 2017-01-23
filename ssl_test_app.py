from flask import *
from flask_json import *
import ssl
import socket
from datetime import *
import dns.resolver
import dns.edns
import dns.flags
import hashlib
import os
import binascii
from queue import Queue, Empty
import paramiko as pm

import util
from forms import *


app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(24)

json = FlaskJSON(app)
app.config['JSON_DATETIME_FORMAT'] = "%Y-%m-%d %H:%M:%S"


@app.route('/')
def main():
    return render_template('base.html')


@app.route('/overview')
def overview():
    data = dict()

    tlsa = list()
    tlsa.append(_make_https_result('www.dafnet.se'))
    tlsa.append(_make_https_result('mail.dafnet.se'))
    tlsa.append(_make_https_result('priv.dafnet.se'))
    tlsa.append(_make_https_result('observ.dafnet.se'))

    tlsa.append(_make_https_result('www.feces.se'))
    tlsa.append(_make_https_result('chat.feces.se'))
    tlsa.append(_make_https_result('git.feces.se'))

    tlsa.append(_make_https_result('mainframe.dafcorp.net'))
    tlsa.append(_make_https_result('datawebb.dafcorp.net'))

    data['tlsa'] = tlsa

    smtp = list()
    smtp.append(_make_smtp_result('mainframe.dafcorp.net'))
    smtp.append(_make_smtp_result('datawebb.dafcorp.net'))

    data['smtp'] = smtp

    sshfp = list()
    sshfp.append(_make_sshfp_result('mainframe.dafcorp.net'))
    sshfp.append(_make_sshfp_result('datawebb.dafcorp.net'))

    data['sshfp'] = sshfp

    return render_template('overview.html', data=data)


@app.route('/api/https/<host>')
@as_json
def api_https(host):
    return _make_https_result(host)


@app.route('/api/https/<host>/<int:port>')
@as_json
def api_https_port(host, port):
    return _make_https_result(host, port)


@app.route('/api/smtp/<host>')
@as_json
def api_smtp(host):
    return _make_smtp_result(host)


@app.route('/api/smtp/<host>/<int:port>')
@as_json
def api_smtp_port(host, port=None):
    return _make_smtp_result(host, port)


@app.route('/api/sshfp/<host>')
@as_json
def api_sshfp(host):
    return _make_sshfp_result(host)


@app.route('/api/sshfp/<host>/<int:port>')
@as_json
def api_sshfp_port(host, port=None):
    return _make_sshfp_result(host, port)


@app.route('/https', methods=['GET', 'POST'])
def https():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = _make_https_result(host, port)
    else:
        form.host.data = 'mainframe.dafcorp.net'
        form.port.data = 443

    return render_template('https.html', form=form, result=result)


@app.route('/smtp', methods=['GET', 'POST'])
def smtp():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = _make_smtp_result(host, port)
    else:
        form.host.data = ''
        form.host.data = 'mainframe.dafcorp.net'
        form.port.data = 25

    return render_template('smtp.html', form=form, result=result)


@app.route('/sshfp', methods=['GET', 'POST'])
def sshfp():
    form = HostForm()
    result = None
    if request.method == 'POST' and form.validate():
        host = form.host.data
        port = form.port.data
        result = _make_sshfp_result(host, port)

    else:
        form.host.data = ''
        form.host.data = 'mainframe.dafcorp.net'
        form.port.data = 22

    return render_template('sshfp.html', form=form, result=result)


def _get_context():
    # return ssl.create_default_context(cafile='ca/ca-sha2.pem')
    return ssl.create_default_context()

def _get_field(s, d):
    for t in d:
        if t[0][0] == s:
            return t[0][1]


def _make_https_result(host, port=443):
    try:
        c, dc = get_cert(host, port)
    except (socket.error, TimeoutError, ssl.SSLError, ssl.CertificateError, dns.exception.DNSException) as e:
        return {'host': host, 'port': port, 'error': str(e)}

    return _make_tlsa_result(host, port, c, dc)


def _make_smtp_result(host, port=25):
    try:
        c, dc = get_cert_smtp(host, port)
    except (socket.error, TimeoutError, ssl.SSLError, ssl.CertificateError, dns.exception.DNSException) as e:
        return {'host': host, 'port': port, 'error': str(e)}

    return _make_tlsa_result(host, port, c, dc)


def _make_sshfp_result(host, port=22):
    try:
        result = dict()
        result['host'] = host
        result['port'] = port
        k = _get_ssh_key(host, port)
        sshfp = _get_sshfp(host)
        result['sshfp'] = sshfp
        result['check'] = _check_sshfp(k, sshfp)
        return result
    except (TimeoutError, dns.exception.DNSException) as e:
        return {'host': host, 'port': port, 'error': str(e)}


def _make_tlsa_result(host, port, c, dc):
    result = dict()
    result['host'] = host
    result['port'] = port
    result['cert'] = _get_cert_data(c)
    result['hash'], result['tlsa'] = _get_tlsa(host, port, dc)
    result['match'] = 'yes' if result['hash'] == result['tlsa'] else 'no'
    return result


def _get_cert_data(c):
    result = dict()
    result['from_d'] = datetime.strptime(c['notBefore'], "%b %d %H:%M:%S %Y %Z")
    result['to_d'] = datetime.strptime(c['notAfter'], "%b %d %H:%M:%S %Y %Z")
    result['cn'] = _get_field('commonName', c['subject'])
    result['an'] = ", ".join([x[1] for x in c['subjectAltName'] if x[0] == 'DNS'])
    return result


def _get_tlsa(host, port, dc):
    try:
        a = get_resolver().query("_%s._tcp.%s." % (port, host), 'TLSA')
        for ans in a:
            if ans.selector == 0:  # full cert
                if ans.mtype == 1:  # SHA256
                    return hashlib.sha256(dc).hexdigest(), binascii.hexlify(a[0].cert).decode()
                elif ans.mtype == 2:  # SHA512
                    return hashlib.sha512(dc).hexdigest(), binascii.hexlify(a[0].cert).decode()
        return 'TLSA ERROR' * 2
    except dns.resolver.NoAnswer:
        return 'NO ANSWER' * 2
    except dns.resolver.NXDOMAIN:
        return ['NXDOMAIN'] * 2


@app.template_global()
def get_cert_smtp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.setblocking(False)

    q = Queue()

    got_tls = False
    starttls_sent = False
    with util.PollThread(s, q) as t:
        t.start()
        while True:
            try:
                l = q.get_nowait()
            except Empty:
                if got_tls and not starttls_sent:
                    s.send(b'STARTTLS\r\n')
                    starttls_sent = True
                else:
                    pass
            else:
                if l.startswith('220 2.0.0'):
                    t.join()
                    break
                elif l.startswith('220'):
                    s.send(b'EHLO 87-249-184-71.ljusnet.se\r\n')
                elif l.startswith('250-STARTTLS'):
                    got_tls = True

        s.setblocking(True)
        ssl_context = _get_context()
        ssl_context.check_hostname = False
        ssl_sock = ssl_context.wrap_socket(s)
        c = ssl_sock.getpeercert()
        dc = ssl_sock.getpeercert(binary_form=True)
        ssl_sock.close()

        return c, dc


@app.template_global()
def get_cert(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_context = _get_context()
    ssl_context.check_hostname = True
    ssl_sock = ssl_context.wrap_socket(s, server_hostname=host)
    ssl_sock.connect((host, port))
    c = ssl_sock.getpeercert()
    dc = ssl_sock.getpeercert(binary_form=True)
    ssl_sock.close()
    return c, dc


# @app.template_global()
def _get_ssh_key(host, port=22):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    t = pm.Transport(s)
    t.start_client()
    k = t.get_remote_server_key()
    t.close()
    s.close()
    return k


def get_resolver():
    r = dns.resolver.Resolver()
    r.nameservers = ['8.8.8.8']
    r.use_edns(0, dns.flags.DO, 1280)
    return r


# @app.template_global()
def get_tlsa(host, port):
    try:
        a = get_resolver().query("_%s._tcp.%s." % (port, host), 'TLSA')
        return binascii.hexlify(a[0].cert).decode()
    except dns.resolver.NoAnswer:
        return 'noanswer'


# @app.template_global()
def _get_sshfp(host):
    reply = list()
    try:
        a = get_resolver().query("%s" % host, 'SSHFP')
        for r in a:
            d = dict()

            if r.algorithm == 1:
                d['algorithm_type'] = 'RSA'
            elif r.algorithm == 2:
                d['algorithm_type'] = 'DSA'
            elif r.algorithm == 3:
                d['algorithm_type'] = 'ECDSA'
            elif r.algorithm == 4:
                d['algorithm_type'] = 'ED25519'
            else:
                d['error'] = 'SSHFP ALGORITHM ERROR (%s)' % r.algorithm
                reply.append(d)
                break
            d['algorithm_code'] = r.algorithm

            if r.fp_type == 1:
                d['fingerprint_type'] = 'SHA-1'
            elif r.fp_type == 2:
                d['fingerprint_type'] = 'SHA-256'
            else:
                d['error'] = 'SSHFP FINGERPRINT ERROR (%s)' % r.fp_type
                reply.append(d)
                break
            d['fingerprint_code'] = r.fp_type
            d['fingerprint'] = binascii.hexlify(r.fingerprint).decode()
            reply.append(d)

    except dns.resolver.NoAnswer as e:
        return [{'error': str(e)}]

    return reply


def _check_sshfp(key, sshfp):
    d = dict()
    if type(key) is pm.rsakey.RSAKey:
        key_type = 1
    elif type(key) is pm.dsskey.DSSKey:
        key_type = 2
    elif type(key) is pm.ecdsakey.ECDSAKey:
        key_type = 3
    else:
        return {'error': 'INVALID_KEY_TYPE'}

    d['key_sshfp_type_code'] = key_type
    d['key_type_str'] = key.get_name()
    d['key_sha1'] = hashlib.sha1(key.asbytes()).hexdigest()
    d['key_sha256'] = hashlib.sha256(key.asbytes()).hexdigest()
    d['sshfp_sha1'] = ''
    d['sshfp_sha256'] = ''
    d['sha1_match'] = ''
    d['sha256_match'] = ''

    fp_found = False
    for i in sshfp:
        if 'error' in i:
            continue
        if i['algorithm_code'] == key_type:
            fp_found = True
            if i['fingerprint_code'] == 1:
                d['sshfp_sha1'] = i['fingerprint']
                d['sha1_match'] = eq_yn(d['key_sha1'], i['fingerprint'])
            elif i['fingerprint_code'] == 2:
                d['sshfp_sha256'] = i['fingerprint']
                d['sha256_match'] = eq_yn(d['key_sha256'], i['fingerprint'])

    if not fp_found:
        return {'error': 'FINGERPRINT_NOT_FOUND'}

    return d


@app.template_global()
def is_none(test):
    return test is None


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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
