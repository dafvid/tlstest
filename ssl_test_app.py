from flask import *
import ssl
import socket
from datetime import *
import dns.resolver
import hashlib
import os
import util
import binascii
from queue import Queue, Empty
from threading import Thread, Event
import io
import paramiko as pm

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


class PollThread(Thread):
    def __init__(self, s, q):
        super(PollThread, self).__init__()
        self.s = s
        self.q = q
        self.stop = Event()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.s.close()

    def run(self):
        buf = io.StringIO()
        while not self.stop.isSet():
            if buf.getvalue():
                buf = io.StringIO()

            while not self.stop.isSet():
                try:
                    data = self.s.recv(1)
                except BlockingIOError:
                    break
                buf.write(str(data.decode()))
                if data.decode() == '\n':
                    break

            self.q.put(buf.getvalue())

    def join(self, timeout=None):
        self.stop.set()
        super(PollThread, self).join(timeout)


@app.template_global()
def get_cert_smtp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.setblocking(False)

    q = Queue()

    got_tls = False
    starttls_sent = False
    with PollThread(s, q) as t:
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
        ssl_context = ssl.create_default_context(cafile='ca/ca-sha2.pem')
        ssl_context.check_hostname = False
        # ssl_context.set_ciphers(
        #     'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:'
        #     'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
        #     '!eNULL:!MD5')

        print(ssl.OPENSSL_VERSION)
        # ssl_sock = ssl_context.wrap_socket(s, do_handshake_on_connect=False)
        ssl_sock = ssl_context.wrap_socket(s)
        # ssl_sock.do_handshake()
        c = ssl_sock.getpeercert()
        # print(c)
        dc = ssl_sock.getpeercert(binary_form=True)
        data = get_cert_data(c)
        data.append(hashlib.sha512(dc).hexdigest())
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
    return data


# class KeyFetcher(pm.client.MissingHostKeyPolicy):
#     def missing_host_key(self, client, hostname, key):


@app.template_global()
def get_ssh_key(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    t = pm.Transport(s)
    t.start_client()
    k = t.get_remote_server_key()
    t.close()
    s.close()
    print(binascii.hexlify(k.get_fingerprint()).decode())
    return k, hashlib.sha256(k.asbytes()).hexdigest()


@app.template_global()
def get_tlsa(host, port):
    a = dns.resolver.query("_%s._tcp.%s." % (port, host), 'TLSA')
    return binascii.hexlify(a[0].cert).decode()


@app.template_global()
def get_sshfp(host, key):
    try:
        a = dns.resolver.query("%s" % host, 'SSHFP')
        key_type = -1
        if type(key) is pm.rsakey.RSAKey:
            key_type = 1
        elif type(key) is pm.dsskey.DSSKey:
            key_type = 2
        elif type(key) is pm.ecdsakey.ECDSAKey:
            key_type = 3
        else:
            return 'ogiltigtyp'
        for r in a:
            if r.algorithm == key_type and r.fp_type == 2:
                return binascii.hexlify(r.fingerprint).decode()
        return 'detsketsig'
    except dns.resolver.NoAnswer:
        return 'noanswer'



@app.template_filter('df')
def df(d):
    return d.strftime('%Y-%m-%d')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
