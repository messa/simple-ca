from collections import namedtuple

CKP = namedtuple('CKP', ('cert', 'key', 'key_password', 'cert_chain'), defaults=(None,))
