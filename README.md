# Usage
`python -m tlstest.cli [cron] <function> <args>`
## arguments
_cron_: cron adjusted outputs

_tlsa_: print TLSA records instead of testing

### functions

_https_: test https (port 443)

_smtp_: test smtp (port 25)

_sshfp_: test sshfp (port 22)

_smimea_: create smimea (define mail and cert)

### values

_host_ host: host to use

_port_ port: port to use

_email_ email: email (user@example.com)

_cert_ path: path to cert file

_file_ filename: file with space separated format _test_ _host_ \[_port_\] \[_mail_\] \[_cert_\]

# TODO
- IMAP test 
