import binascii
import hashlib
import os
import socket
import ssl
import struct
from datetime import datetime
from pprint import pprint
from smtplib import SMTP

import dns.resolver
import dns.zone
import paramiko as pm
from dns.exception import DNSException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from .util import eq_yn, yn

__version__ = '200107.1'


def _get_resolver():
    r = dns.resolver.Resolver()
    # r.nameservers = ['8.8.8.8']
    r.use_edns(0, dns.flags.DO, 1280)
    return r


def _get_context(check_hostname=False):
    c = ssl.create_default_context()
    c.check_hostname = check_hostname
    c.verify_mode = ssl.CERT_OPTIONAL

    return c


def _get_cert(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_context = _get_context(True)
    # ssl_context.check_hostname = True
    ssl_sock = ssl_context.wrap_socket(s, server_hostname=host)
    ssl_sock.connect((host, port))
    # c = ssl_sock.getpeercert()
    dc = ssl_sock.getpeercert(binary_form=True)
    ssl_sock.close()
    c = x509.load_der_x509_certificate(dc, default_backend())

    return c


def _get_cert_smtp(host, port):
    # print("Fetch SMTP cert for %s:%s" % (host, port))
    with SMTP(host, port) as client:
        # client.set_debuglevel(True)
        client.ehlo_or_helo_if_needed()
        ssl_context = _get_context(False)
        client.starttls(context=ssl_context)
        # c = client.sock.getpeercert()
        dc = client.sock.getpeercert(binary_form=True)
        c = x509.load_der_x509_certificate(dc, default_backend())

    return c


def _get_cert_file(path):
    with open(path) as f:
        data = f.read()
        c = x509.load_pem_x509_certificate(data.encode(), default_backend())
        return c


def _get_field(s, d):
    for t in d:
        if t[0][0] == s:
            return t[0][1]


def _get_cert_data(c):
    result = dict()
    result['from_d'] = c.not_valid_before
    result['to_d'] = c.not_valid_after
    result['cn'] = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ext = c.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    result['an'] = ext.value.get_values_for_type(x509.DNSName)
    result['issuer'] = "{}, {}, {}".format(
        c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
        c.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    )
    cder = c.public_bytes(serialization.Encoding.DER)
    result['sha256'] = hashlib.sha256(cder).hexdigest()
    result['sha512'] = hashlib.sha512(cder).hexdigest()

    pkb = c.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    result['spki_sha256'] = hashlib.sha256(pkb).hexdigest()
    result['spki_sha512'] = hashlib.sha512(pkb).hexdigest()

    return result


def _get_tlsa(host, port):
    tlsa = dict()
    error = list()
    try:
        a = _get_resolver().query("_%s._tcp.%s." % (port, host), 'TLSA')
        tlsa['ad'] = yn('AD' in dns.flags.to_text(a.response.flags))
        for ans in a:
            if ans.usage == 3:
                tlsa['selector'] = ans.selector
                if ans.selector == 0:  # full cert
                    if ans.mtype == 1:  # SHA256
                        if 'sha256' in tlsa:
                            error.append('MULTIPLE SHA256 RECORDS')
                        tlsa['sha256'] = binascii.hexlify(ans.cert).decode()
                    elif ans.mtype == 2:  # SHA512
                        if 'sha512' in tlsa:
                            error.append('MULTIPLE SHA512 RECORDS')
                        tlsa['sha512'] = binascii.hexlify(ans.cert).decode()
                    else:
                        error.append('UNKNOWN HASH: %s' % ans.mtype)
                elif ans.selector == 1:  # SPKI
                    if ans.mtype == 1:  # SHA256
                        if 'spki_sha256' in tlsa:
                            error.append('MULTIPLE SPKI SHA256 RECORDS')
                        tlsa['spki_sha256'] = binascii.hexlify(
                            ans.cert).decode()
                    elif ans.mtype == 2:  # SHA512
                        if 'spki_sha512' in tlsa:
                            error.append('MULTIPLE SPKI SHA512 RECORDS')
                        tlsa['spki_sha512'] = binascii.hexlify(
                            ans.cert).decode()
                    else:
                        error.append('UNKNOWN SPKI HASH: %s' % ans.mtype)
                else:
                    error.append('UNKNOWN SELECTOR: %s' % ans.selector)
            else:
                error.append('UNKNOWN USAGE')
    except dns.exception.DNSException as e:
        error.append(str(e))

    tlsa['error'] = error

    return tlsa


def _check_tlsa(cert, tlsa):
    check = dict()
    check['match_sha256'] = yn(
        'sha256' in tlsa and cert['sha256'] == tlsa['sha256'])
    check['match_sha512'] = yn(
        'sha512' in tlsa and cert['sha512'] == tlsa['sha512'])
    check['match_spki_sha256'] = yn(
        'spki_sha256' in tlsa and cert['spki_sha256'] == tlsa['spki_sha256'])
    check['match_spki_sha512'] = yn(
        'spki_sha512' in tlsa and cert['spki_sha512'] == tlsa['spki_sha512'])
    return check


def _make_result(result_type, do_query=True, host=None, port=None, file=None):
    result = dict()
    error = list()
    result['port'] = port
    try:
        if result_type == 'https':
            result['host'] = host
            c = _get_cert(host, port)
        elif result_type == 'smtp':
            result['host'] = host
            c = _get_cert_smtp(host, port)
        elif result_type == 'file':
            result['host'] = '<file>'
            c = _get_cert_file(file)
        else:
            raise Exception("Unknown type")
        cert = _get_cert_data(c)
        result['cert'] = cert
        if do_query:
            tlsa = _get_tlsa(host, port)
            result['tlsa'] = tlsa
            result['check'] = _check_tlsa(cert, tlsa)
        result['records'] = _make_tlsa_records(cert, port)
    except (socket.error, TimeoutError, ssl.SSLError, ssl.CertificateError,
            dns.exception.DNSException) as e:
        error.append("{}:{} {}".format(host, port, e))

    result['error'] = error

    return result


def _make_tlsa_records(cert, port):
    hosts = [x for x in cert['an']]
    cn = cert['cn']
    if cn not in hosts:
        hosts.append(cn)

    if not hosts:
        return list()

    host = hosts[0]  # TODO Multiple domains
    if host.count('.') == 1:
        domain = host
    elif host.count('.') > 1:
        domain = host[host.rfind('.', 0, host.rfind('.')) + 1:]
    else:
        return list()

    z = dns.zone.BadZone()
    z.origin = domain
    records = list()
    for h in hosts:
        if h == domain:
            host = ''
        else:
            host = '.' + h[:h.find(domain) - 1]

        for u in (3,):  # usage
            for s in (0, 1):  # selector
                for t in (1, 2):
                    if s == 0 and t == 1:
                        d = cert['sha256']
                    elif s == 0 and t == 2:
                        d = cert['sha512']
                    elif s == 1 and t == 1:
                        d = cert['spki_sha256']
                    elif s == 1 and t == 2:
                        d = cert['spki_sha512']

                    r = "_%s._tcp%s IN TLSA %s %s %s %s" % (
                        port, host, u, s, t, d)
                    records.append(r)

    return records


def make_https_result(host, port=443, do_query=True):
    return _make_result('https', host=host, port=port, do_query=do_query)


def make_smtp_result(host, port=25, do_query=True):
    return _make_result('smtp', host=host, port=port, do_query=do_query)


def make_file_result(file, port, do_query=True):
    return _make_result('file', port=port, file=file, do_query=do_query)


def _get_ssh_key(host, port=22):
    key_d = dict()
    keys = dict()
    error = list()
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect((host, port))
    t1 = pm.Transport(s1)
    so1 = t1.get_security_options()

    rsa_types = [x for x in so1.key_types if 'rsa' in x]
    dsa_types = [x for x in so1.key_types if 'dss' in x]
    ecdsa_types = [x for x in so1.key_types if 'ecdsa' in x]

    t1.close()
    s1.close()

    def get_keys(types):
        d = dict()
        for ty in types:
            # print("Trying:", ty)
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.connect((host, port))
            t2 = pm.Transport(s2)
            so = t2.get_security_options()
            try:
                so.key_types = [ty]
                t2.start_client()
                key = t2.get_remote_server_key()
                t2.close()
                s2.close()

                if type(key) is pm.rsakey.RSAKey:
                    key_type = 1
                elif type(key) is pm.dsskey.DSSKey:
                    key_type = 2
                elif type(key) is pm.ecdsakey.ECDSAKey:
                    key_type = 3
                else:
                    continue

                d['sshfp_type_code'] = key_type
                d['type_str'] = key.get_name()
                d['sha1'] = hashlib.sha1(key.asbytes()).hexdigest()
                d['sha256'] = hashlib.sha256(key.asbytes()).hexdigest()
                break
            except (Exception, ValueError, pm.SSHException,
                    pm.ssh_exception.SSHException) as e:
                error.append("{}: {}".format(ty, str(e)))
            t2.close()
            s2.close()
        return d

    k = get_keys(rsa_types)
    if k:
        keys['rsa'] = k
    k = get_keys(dsa_types)
    if k:
        keys['dsa'] = k
    k = get_keys(ecdsa_types)
    if k:
        keys['ecdsa'] = k
    key_d['keys'] = keys
    if error:
        key_d['error'] = error

    return key_d


def _get_sshfp(host):
    reply = dict()
    rrd = list()
    try:
        a = _get_resolver().query("%s" % host, 'SSHFP')
        reply['ad'] = yn('AD' in dns.flags.to_text(a.response.flags))
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
                rrd.append(
                    {'error': 'SSHFP ALGORITHM ERROR (%s)' % r.algorithm})
                break
            d['algorithm_code'] = r.algorithm

            if r.fp_type == 1:
                d['fingerprint_type'] = 'SHA-1'
            elif r.fp_type == 2:
                d['fingerprint_type'] = 'SHA-256'
            else:
                rrd.append(
                    {'error': 'SSHFP FINGERPRINT ERROR (%s)' % r.algorithm})
                break
            d['fingerprint_code'] = r.fp_type
            d['fingerprint'] = binascii.hexlify(r.fingerprint).decode()
            rrd.append(d)

    except dns.resolver.NoAnswer as e:
        return {'error': str(e)}

    reply['rrd'] = rrd
    return reply


def _check_sshfp(key, sshfp):
    d = dict()

    fp_found = False
    key_types = {1: 'rsa', 2: 'dsa', 3: 'ecdsa', 4: 'ed25519'}

    for i in sshfp['rrd']:
        type_code = i['algorithm_code']
        if type_code in key_types:
            key_type = key_types[type_code]
            if key_type in key:
                k = key[key_type]
                if 'error' not in k:
                    fp_found = True
                    if key_type not in d:
                        d[key_type] = dict()
                    if i['fingerprint_code'] == 1:
                        d[key_type]['sshfp_sha1'] = i['fingerprint']
                        d[key_type]['key_sha1'] = k['sha1']
                        d[key_type]['sha1_match'] = eq_yn(k['sha1'],
                                                          i['fingerprint'])
                    elif i['fingerprint_code'] == 2:
                        d[key_type]['sshfp_sha256'] = i['fingerprint']
                        d[key_type]['key_sha256'] = k['sha256']
                        d[key_type]['sha256_match'] = eq_yn(k['sha256'],
                                                            i['fingerprint'])

    if not fp_found:
        return {'error': 'FINGERPRINT_NOT_FOUND'}

    return d


def make_sshfp_result(host, port=22):
    result = dict()
    result['host'] = host
    h = ''
    if host.count('.') == 2:
        h = host[:host.find('.')]
    result['port'] = port
    error = list()
    records = list()
    try:
        kd = _get_ssh_key(host, port)
        k = kd['keys']
        if kd['error']:
            error.extend(kd['error'])
        result['key'] = k
        if h:
            for n, i in k.items():
                if n != 'error':
                    for j in (1, 2):
                        key_hash = i['sha1'] if j == 1 else i['sha256']
                        records.append("{} IN SSHFP {} {} {}".format(h, i[
                            'sshfp_type_code'], j, key_hash))
            result['records'] = records
        sshfp = _get_sshfp(host)
        if 'error' in sshfp:
            error.append(sshfp['error'])
        else:
            result['sshfp'] = sshfp
            result['check'] = _check_sshfp(k, sshfp)
    except (TimeoutError, dns.exception.DNSException) as e:
        error.append(str(e))

    if error:
        result['error'] = error

    return result


def make_smimea(mail, cert):
    mail = mail.split('@')
    if len(mail) != 2:
        raise Exception('mail must have format <user>@<host>')
    cert = cert.encode('utf-8')
    c = x509.load_pem_x509_certificate(cert, default_backend())
    b = c.public_bytes(encoding=serialization.Encoding.DER)
    spki = c.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    name = hashlib.sha256(mail[0].encode('UTF-8')).hexdigest()[:56]
    rq = "%s._smimecert.%s. IN TYPE53" % (name, mail[1])
    recs = list()
    u = 3  # Usage certificate
    for s in (0, 1):  # Selector 0=Certificate 1=SPKI
        for t in (0, 1, 2):  # Type 0=Full 1=SHA256 2=SHA512
            if s == 0:
                d = b
            elif s == 1:
                d = spki
            else:
                raise Exception("Selector error [{}]".format(s))

            if t == 0:
                h = binascii.hexlify(b).decode('UTF-8')
            elif t == 1:
                h = hashlib.sha256(d).hexdigest()
            elif t == 2:
                h = hashlib.sha512(d).hexdigest()
            else:
                raise Exception("Type error [{}]".format(t))

            rec = "%s %d %d %d %s" % (rq, u, s, t, h)
            if s == 1 and t == 0:
                continue
            recs.append(rec)
    return recs


def make_ds(host, port=53):
    pass


def make_fetch_smimea(mail):
    nd = {
        'selector': {0: 'cert', 1: 'spki'},
        'type': {0: 'full', 1: 'sha256', 2: 'sha512'}
    }
    reply = {
        'cert': {'sha256': None, 'sha512': None},
        'spki': {'sha256': None, 'sha512': None},
    }
    mail = mail.split('@')
    local = mail[0]
    host = mail[1]
    name = hashlib.sha256(local.encode('UTF-8')).hexdigest()[:56]
    q = '{}._smimecert.{}'.format(name, host)
    reply['query'] = q
    try:
        a = _get_resolver().query(q, 'TYPE53')
    except DNSException as e:
        raise util.TLSTestException(e)
    reply['ad'] = yn('AD' in dns.flags.to_text(a.response.flags))
    for r in a:
        usage, selector, _type = struct.unpack('!BBB', r.data[0:3])
        data = r.data[3:].unwrap()
        assert usage == 3
        if selector == 0 and _type == 0:
            data = x509.load_der_x509_certificate(data, default_backend()).public_bytes(serialization.Encoding.PEM).decode()
        else:
            data = binascii.hexlify(data).decode()
        reply[nd['selector'][selector]][nd['type'][_type]] = data

    return reply
