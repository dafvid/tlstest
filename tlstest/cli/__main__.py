import os
import sys
from pprint import pprint

from .. import make_https_result, make_smtp_result, make_sshfp_result, \
    make_smimea
from ..util import parse_args, parse_flargs

argv = sys.argv
args = parse_args(('file', 'host', 'port'), True)
flargs = parse_flargs((
    'cron',
    'https',
    'smtp',
    'sshfp',
    'ds',
    'smimea'))


def _print_result(r, r_type):
    if r['error']:
        print()
        for e in r['error']:
            print(e)
    else:
        if not flargs['cron']:
            print()
            print("[ {}: {} ]".format(r['host'], r['port']))
            print()
            print("ISSUER: {}".format(r['cert']['issuer']))
            print("CN: {}".format(r['cert']['cn']))
            print("AN: {}".format(r['cert']['an']))
            print("FROM: {}".format(r['cert']['from_d']))
            print("TO: {}".format(r['cert']['to_d']))
            print()

        for k, v in r['check'].items():
            if v == 'no':
                print('ERROR: {} {} TLSA {}'.format(r['host'],
                                                    r_type.upper(),
                                                    k[
                                                    k.find('_') + 1:].upper()))

        if not flargs['cron']:
            print()
            for rec in r['records']:
                print(rec)


def _https(host, port):
    if not port:
        port = 443
    r = make_https_result(host, port)
    _print_result(r, 'https')


def _smtp(host, port):
    if not port:
        port = 25
    r = make_smtp_result(host, port)
    _print_result(r, 'smtp')


def _sshfp(host, port):
    if not port:
        port = 22
    r = make_sshfp_result(host, port)
    pprint(r)
    print()
    if r['error']:
        for e in r['error']:
            print(e)
    if not flargs['cron']:
        print("[ SSH {}: {} ]".format(host, port))
        print()
        print("ISSUER: {}".format(r['cert']['issuer']))
        print("CN: {}".format(r['cert']['cn']))
        print("AN: {}".format(r['cert']['an']))
        print("FROM: {}".format(r['cert']['from_d']))
        print("TO: {}".format(r['cert']['to_d']))
        print()

    for k, v in r['check'].items():
        if v == 'no':
            print('ERROR: {} SSHFP {}'.format(r['host'],
                                              k.upper()))

    if not flargs['cron']:
        print()
        for rec in r['records']:
            print(rec)


if args['file']:
    fn = args['file']
    if not os.path.exists(fn):
        raise FileNotFoundError(fn)
    else:
        with open(fn) as f:
            for l in f.readlines():
                if l.startswith('#'):
                    continue
                l = l.strip()
                parts = l.split(' ')
                if len(parts) == 3:
                    func, host, port = parts
                elif len(parts) == 2:
                    func, host = parts
                    port = None
                else:
                    raise Exception("Bad line {}".format(l))

                if func == 'https':
                    _https(host, port)
                elif func == 'smtp':
                    _smtp(host, port)
                elif func == 'sshfp':
                    _sshfp(host, port)
                else:
                    raise Exception("Unknown function: {}".format(func))

else:
    if flargs['https']:
        assert args['host']
        port = int(args['port']) if args['port'] else 443
        _https(args['host'], port)
    if flargs['smtp']:
        assert args['host']
        port = int(args['port']) if args['port'] else 25
        _smtp(args['host'], port)
    if flargs['sshfp']:
        assert args['host']
        port = int(args['port']) if args['port'] else 22
        _sshfp(args['host'], port)
