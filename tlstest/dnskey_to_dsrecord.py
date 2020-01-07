"""
Generate a DNSSEC DS record based on the incoming DNSKEY record

The DNSKEY can be found using for example 'dig':

$ dig DNSKEY secure.widodh.nl

The output can then be parsed with the following code to generate a DS record
for in the parent DNS zone

Author: Wido den Hollander <wido@widodh.nl>

Many thanks to this blogpost: https://www.v13.gr/blog/?p=239
"""

import struct
import base64
import hashlib


def _calc_keyid(flags, protocol, algorithm, dnskey):
    st = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st += base64.b64decode(dnskey)

    cnt = 0
    for idx in range(len(st)):
        s = struct.unpack('B', st[idx:idx+1])[0]
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s

    return ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF


def _calc_ds(domain, flags, protocol, algorithm, dnskey):
    if domain.endswith('.') is False:
        domain += '.'

    signature = bytes()
    for i in domain.split('.'):
        signature += struct.pack('B', len(i)) + i.encode()

    signature += struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    signature += base64.b64decode(dnskey)

    return {
        'sha1':    hashlib.sha1(signature).hexdigest().upper(),
        'sha256':  hashlib.sha256(signature).hexdigest().upper(),
    }


def dnskey_to_ds(domain, dnskey):
    dnskeylist = dnskey.split(' ', 3)

    flags = dnskeylist[0]
    protocol = dnskeylist[1]
    algorithm = dnskeylist[2]
    key = dnskeylist[3].replace(' ', '')

    keyid = _calc_keyid(flags, protocol, algorithm, key)
    ds = _calc_ds(domain, flags, protocol, algorithm, key)

    ret = list()
    for i, v in enumerate(('sha1', 'sha256')):
        ret_d = dict()
        ret_d['keytag'] = keyid
        ret_d['alg'] = algorithm
        ret_d['digest_type'] = i + 1
        ret_d['digest'] = ds[v].lower()
        ret_d['record'] = "{keytag} {alg} {digest_type} {digest}".format(**ret_d)
        ret.append(ret_d)
    return ret
