from .types import CKP
from .openssl_cli import OpenSSLCLI
from .functions.init_ca import InitCA
from .functions.create_server_cert import CreateServerCert


class CA (CKP):
    '''
    Certificate Authority with cert, key and key_password.

    Inherits from CKP namedtuple, so it supports attribute access,
    tuple unpacking and indexing.

    Create a new CA using the class method :meth:`init_ca`,
    or construct directly from existing PEM data.
    '''

    def __new__(cls, cert, key, key_password):
        '''
        Construct a CA from existing PEM data.

        :param cert: CA certificate (PEM-encoded string)
        :param key: CA private key (PEM-encoded string)
        :param key_password: password to the CA private key
        '''
        # Using __new__ instead of __init__ because namedtuple
        # instances are created in __new__, not __init__.
        return super().__new__(cls, cert=cert, key=key, key_password=key_password)

    @classmethod
    def init_ca(cls, org, cn='CA'):
        '''
        Create a new Certificate Authority.

        :param org: Organization Name
        :param cn: Common Name (default: 'CA')
        :return: CA instance with generated cert, key and key_password
        '''
        openssl_cli = OpenSSLCLI()
        x = InitCA(openssl_cli)
        x.run(org=org, cn=cn)
        return cls(cert=x.cert, key=x.key, key_password=x.key_password)

    def create_server_cert(self, cn, org, dc=None, san=None):
        '''
        Create a server certificate signed by this CA.

        :param cn: Common Name, typically the server hostname
        :param org: Organization Name
        :param dc: Domain Component (optional)
        :param san: list of Subject Alternative Names, e.g. ['DNS:localhost', '10.0.0.1'] (optional)
        :return: CKP namedtuple with cert, key and key_password
        '''
        openssl_cli = OpenSSLCLI()
        x = CreateServerCert(
            openssl_cli,
            ca_cert=self.cert, ca_key=self.key, ca_key_password=self.key_password)
        x.run(cn=cn, org=org, dc=dc, san=san)
        return CKP(cert=x.cert, key=x.key, key_password=x.key_password)
