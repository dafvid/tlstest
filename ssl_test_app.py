from flask import *
import ssl
import socket
from datetime import *
import dns.resolver
import hashlib
import os

app = Flask(__name__)
app.debug = True


@app.route('/')
def main():
    return render_template('main.html')


def get_field(s, d):
    for t in d:
        if t[0][0] == s:
            return t[0][1]


def get_cert_data(c):
    # print(c)
    from_d = datetime.strptime(c['notBefore'], "%b %d %H:%M:%S %Y %Z")
    to_d = datetime.strptime(c['notAfter'], "%b %d %H:%M:%S %Y %Z")
    cn = get_field('commonName', c['subject'])
    an = ", ".join([x[1] for x in c['subjectAltName'] if x[0] == 'DNS'])
    return [from_d, to_d, cn, an]


@app.template_global()
def get_cert_smtp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # s.setblocking(False)
    ssl_context = ssl.create_default_context(cafile='ca/ca-sha2.pem')
    f = s.makefile()
    while True:
        l = f.readline()
        print(l)
        if l.startswith('220'):
            s.send(b'ehlo 87-249-184-71.ljusnet.se\r\n')
        elif l.startswith('250 STARTTLS'):
            s.send(b'starttls\r\n')
            break

    ssl_sock = ssl_context.wrap_socket(s, server_hostname=host)
    # ssl_sock.connect((host, port))
    c = ssl_sock.getpeercert()
    dc = ssl_sock.getpeercert(binary_form=True)
    data = get_cert_data(c)
    data.append(hashlib.sha512(dc).hexdigest())
    data.append(
        dns.resolver.Resolver().query("_%s._tcp.%s." % (port, host), 'TLSA').response.answer[0].to_text().split()[7])
    return data


@app.template_global()
def get_cert(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ca')
    ssl_context = ssl.create_default_context(cafile=os.path.join(ca_path, 'ca-sha2.pem'))
    ssl_sock = ssl_context.wrap_socket(s, server_hostname=host)
    ssl_sock.connect((host, port))
    c = ssl_sock.getpeercert()
    dc = ssl_sock.getpeercert(binary_form=True)
    data = get_cert_data(c)
    data.append(hashlib.sha512(dc).hexdigest())
    data.append(
        dns.resolver.Resolver().query("_%s._tcp.%s." % (port, host), 'TLSA').response.answer[0].to_text().split()[7])
    return data


@app.template_global()
def get_tlsa(host, port):
    print("_%s._tcp.%s." % (port, host))
    return dns.resolver.Resolver().query("_%s._tcp.%s." % (port, host), 'TLSA').response.answer[0].to_text().split()[7]


@app.template_filter('df')
def df(d):
    return d.strftime('%Y-%m-%d')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
