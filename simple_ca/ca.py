from .types import CKP
from .openssl_cli import OpenSSLCLI
from .functions.init_ca import InitCA
from .functions.create_intermediate_ca import CreateIntermediateCA
from .functions.create_server_cert import CreateServerCert


class CA(CKP):
    """
    Certificate Authority with cert, key and key_password.

    Inherits from CKP namedtuple, so it supports attribute access,
    tuple unpacking and indexing.

    Create a new CA using the class method :meth:`init_ca`,
    or construct directly from existing PEM data.
    """

    def __new__(cls, cert, key, key_password, cert_chain=None, *, _openssl_cli=None, _chain_pem='', _verify_chain=None):
        """
        Construct a CA from existing PEM data.

        :param cert: CA certificate (PEM-encoded string)
        :param key: CA private key (PEM-encoded string)
        :param key_password: password to the CA private key
        :param cert_chain: full certificate chain (PEM-encoded string, optional)
        """
        # Using __new__ instead of __init__ because namedtuple
        # instances are created in __new__, not __init__.
        obj = super().__new__(cls, cert=cert, key=key, key_password=key_password, cert_chain=cert_chain)
        obj._openssl_cli = _openssl_cli or OpenSSLCLI()
        # _chain_pem: intermediate certs to append when building cert_chain for leaf certs.
        # Empty string for root CA, intermediate cert(s) PEM for intermediate CAs.
        obj._chain_pem = _chain_pem
        # _verify_chain: full CA bundle (all CA certs from this CA up to root) for openssl verify.
        obj._verify_chain = _verify_chain if _verify_chain is not None else cert
        return obj

    @classmethod
    def init_ca(cls, org, cn='CA', *, _openssl_cli=None):
        """
        Create a new Certificate Authority.

        :param org: Organization Name
        :param cn: Common Name (default: 'CA')
        :return: CA instance with generated cert, key and key_password
        """
        openssl_cli = _openssl_cli or OpenSSLCLI()
        x = InitCA(openssl_cli)
        x.run(org=org, cn=cn)
        return cls(
            cert=x.cert,
            key=x.key,
            key_password=x.key_password,
            _openssl_cli=openssl_cli,
            _chain_pem='',
            _verify_chain=x.cert,
        )

    def create_intermediate_ca(self, org, cn='Intermediate CA'):
        """
        Create an intermediate CA signed by this CA.

        :param org: Organization Name
        :param cn: Common Name (default: 'Intermediate CA')
        :return: CA instance for the intermediate CA
        """
        x = CreateIntermediateCA(
            self._openssl_cli,
            ca_cert=self.cert,
            ca_key=self.key,
            ca_key_password=self.key_password,
            ca_verify_chain=self._verify_chain,
        )
        x.run(org=org, cn=cn)
        chain_pem = x.cert + self._chain_pem
        verify_chain = x.cert + self._verify_chain
        return CA(
            cert=x.cert,
            key=x.key,
            key_password=x.key_password,
            cert_chain=chain_pem,
            _openssl_cli=self._openssl_cli,
            _chain_pem=chain_pem,
            _verify_chain=verify_chain,
        )

    def create_server_cert(self, cn, org, dc=None, san=None):
        """
        Create a server certificate signed by this CA.

        :param cn: Common Name, typically the server hostname
        :param org: Organization Name
        :param dc: Domain Component (optional)
        :param san: list of Subject Alternative Names, e.g. ['DNS:localhost', '10.0.0.1'] (optional)
        :return: CKP namedtuple with cert, key, key_password and cert_chain
        """
        x = CreateServerCert(
            self._openssl_cli,
            ca_cert=self.cert,
            ca_key=self.key,
            ca_key_password=self.key_password,
            ca_verify_chain=self._verify_chain,
        )
        x.run(cn=cn, org=org, dc=dc, san=san)
        cert_chain = x.cert + self._chain_pem
        return CKP(cert=x.cert, key=x.key, key_password=x.key_password, cert_chain=cert_chain)
