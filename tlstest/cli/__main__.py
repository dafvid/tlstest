import sys
from pprint import pprint

from .. import make_https_result
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


def _https(host, port=443):
    r = make_https_result(args['host'], port)

    if not flargs['cron']:
        print("[ {}: {} ]".format(args['host'], port))
        print()
        print("ISSUER: {}".format(r['cert']['issuer']))
        print("CN: {}".format(r['cert']['cn']))
        print("AN: {}".format(r['cert']['an']))
        print("FROM: {}".format(r['cert']['from_d']))
        print("TO: {}".format(r['cert']['to_d']))
        print()

    for k, v in r['check'].items():
        if v == 'no':
            print('{} TLSA {} ERROR'.format(args['host'],
                                            k[k.find('_') + 1:].upper()))
    print()
    if not flargs['cron']:
        for rec in r['records']:
            print(rec)


if flargs['https']:
    assert args['host']
    port = int(args['port']) if args['port'] else 443
    _https(args['host'], 443)

    # pprint(r)
