from collections import namedtuple

DEFAULT_VALIDITY_DAYS = 10000

CKP = namedtuple('CKP', ('cert', 'key', 'key_password', 'cert_chain', 'serial'), defaults=(None, None))
