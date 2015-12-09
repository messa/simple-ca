from collections import namedtuple
import logging

from .functions.init_ca import InitCA
from .functions.create_server_cert import CreateServerCert
from .openssl_cli import OpenSSLCLI

logger = logging.getLogger(__name__)


CKP = namedtuple('CKP', ('cert', 'key', 'key_password'))


class SimpleCA:
    '''
    This is the main API.
    '''

    def __init__(self):
        self.logger = logger
        self.openssl_cli = OpenSSLCLI()

    def init_ca(self, org, cn='CA'):
        x = InitCA(self.openssl_cli)
        x.run(org=org, cn=cn)
        return CKP(cert=x.cert, key=x.key, key_password=x.key_password)

    def create_server_cert(self, ca_cert, ca_key, ca_key_password, cn, org, dc=None):
        '''
        Keyword arguments:
        - ca_cert: use value ca.cert from ca obtained from init_ca()
        - ca_key: use value ca.key from ca obtained from init_ca()
        - ca_key_password: use value ca.key_password from ca obtained from init_ca()
        - cn: Common Name, most likely server hostname
        - org: Organization Name, most likely should be the same as CA org
        - dc: Domain Component
        '''
        x = CreateServerCert(self.openssl_cli, ca_cert=ca_cert, ca_key=ca_key, ca_key_password=ca_key_password)
        x.run(cn=cn, org=org, dc=dc)
        return CKP(cert=x.cert, key=x.key, key_password=x.key_password)
