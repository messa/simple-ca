from .types import CKP, DEFAULT_VALIDITY_DAYS
from .openssl_cli import OpenSSLCLI
from .functions.init_ca import InitCA
from .functions.create_intermediate_ca import CreateIntermediateCA
from .functions.create_server_cert import CreateServerCert


class _CABase(CKP):
    """
    Base class for Certificate Authorities.

    Provides shared functionality for creating intermediate CAs
    and server certificates. Not intended to be instantiated directly.
    """

    def create_intermediate_ca(self, org, cn='Intermediate CA', *, days=DEFAULT_VALIDITY_DAYS):
        """
        Create an intermediate CA signed by this CA.

        :param org: Organization Name
        :param cn: Common Name (default: 'Intermediate CA')
        :param days: certificate validity in days (default: DEFAULT_VALIDITY_DAYS)
        :return: IntermediateCA instance
        """
        x = CreateIntermediateCA(
            self._openssl_cli,
            ca_cert=self.cert,
            ca_key=self.key,
            ca_key_password=self.key_password,
            ca_verify_chain=self._verify_chain,
        )
        x.run(org=org, cn=cn, days=days)
        chain_pem = x.cert + self._chain_pem
        verify_chain = x.cert + self._verify_chain
        return IntermediateCA(
            cert=x.cert,
            key=x.key,
            key_password=x.key_password,
            cert_chain=chain_pem,
            serial=x.serial,
            _openssl_cli=self._openssl_cli,
            _chain_pem=chain_pem,
            _verify_chain=verify_chain,
        )

    def create_server_cert(self, cn, org, dc=None, san=None, *, days=DEFAULT_VALIDITY_DAYS):
        """
        Create a server certificate signed by this CA.

        :param cn: Common Name, typically the server hostname
        :param org: Organization Name
        :param dc: Domain Component (optional)
        :param san: list of Subject Alternative Names, e.g. ['DNS:localhost', '10.0.0.1'] (optional)
        :param days: certificate validity in days (default: DEFAULT_VALIDITY_DAYS)
        :return: CKP namedtuple with cert, key, key_password, cert_chain and serial
        """
        x = CreateServerCert(
            self._openssl_cli,
            ca_cert=self.cert,
            ca_key=self.key,
            ca_key_password=self.key_password,
            ca_verify_chain=self._verify_chain,
        )
        x.run(cn=cn, org=org, dc=dc, san=san, days=days)
        cert_chain = x.cert + self._chain_pem
        return CKP(cert=x.cert, key=x.key, key_password=x.key_password, cert_chain=cert_chain, serial=x.serial)


class RootCA(_CABase):
    """
    Root Certificate Authority.

    Inherits from CKP namedtuple, so it supports attribute access,
    tuple unpacking and indexing.

    Create a new root CA using the class method :meth:`init_ca`,
    or construct directly from existing PEM data.
    """

    def __new__(
        cls,
        cert,
        key,
        key_password,
        cert_chain=None,
        serial=None,
        *,
        _openssl_cli=None,
        _chain_pem='',
        _verify_chain=None,
    ):
        """
        Construct a root CA from existing PEM data.

        :param cert: CA certificate (PEM-encoded string)
        :param key: CA private key (PEM-encoded string)
        :param key_password: password to the CA private key
        :param cert_chain: full certificate chain (PEM-encoded string, optional)
        :param serial: certificate serial number (hex string, optional)
        """
        # Using __new__ instead of __init__ because namedtuple
        # instances are created in __new__, not __init__.
        obj = super().__new__(cls, cert=cert, key=key, key_password=key_password, cert_chain=cert_chain, serial=serial)
        obj._openssl_cli = _openssl_cli or OpenSSLCLI()
        obj._chain_pem = _chain_pem
        obj._verify_chain = _verify_chain if _verify_chain is not None else cert
        return obj

    @classmethod
    def init_ca(cls, org, cn='CA', *, days=DEFAULT_VALIDITY_DAYS, _openssl_cli=None):
        """
        Create a new Certificate Authority.

        :param org: Organization Name
        :param cn: Common Name (default: 'CA')
        :param days: certificate validity in days (default: DEFAULT_VALIDITY_DAYS)
        :return: RootCA instance with generated cert, key and key_password
        """
        openssl_cli = _openssl_cli or OpenSSLCLI()
        x = InitCA(openssl_cli)
        x.run(org=org, cn=cn, days=days)
        return cls(
            cert=x.cert,
            key=x.key,
            key_password=x.key_password,
            serial=x.serial,
            _openssl_cli=openssl_cli,
            _chain_pem='',
            _verify_chain=x.cert,
        )


class IntermediateCA(_CABase):
    """
    Intermediate Certificate Authority.

    Inherits from CKP namedtuple, so it supports attribute access,
    tuple unpacking and indexing.

    Create a new intermediate CA using :meth:`RootCA.create_intermediate_ca`
    (or :meth:`IntermediateCA.create_intermediate_ca`),
    or construct directly from existing PEM data by providing
    either a ``parent`` CA object or a ``parent_ca_cert`` PEM string.
    """

    def __new__(
        cls,
        cert,
        key,
        key_password,
        *,
        parent=None,
        parent_ca_cert=None,
        cert_chain=None,
        serial=None,
        _openssl_cli=None,
        _chain_pem=None,
        _verify_chain=None,
    ):
        """
        Construct an intermediate CA from existing PEM data.

        Either ``parent`` or ``parent_ca_cert`` must be provided (but not both)
        when constructing from existing data (i.e. when ``_chain_pem`` is not given).

        :param cert: intermediate CA certificate (PEM-encoded string)
        :param key: intermediate CA private key (PEM-encoded string)
        :param key_password: password to the private key
        :param parent: parent CA object (RootCA or IntermediateCA) — chain context is derived automatically
        :param parent_ca_cert: parent CA certificate (PEM-encoded string) — alternative to parent
        :param cert_chain: full certificate chain (PEM-encoded string, optional — computed automatically)
        :param serial: certificate serial number (hex string, optional)
        """
        if _chain_pem is not None:
            # Internal construction path (from create_intermediate_ca).
            chain_pem = _chain_pem
            verify_chain = _verify_chain
        elif parent is not None and parent_ca_cert is not None:
            raise ValueError('Specify either parent or parent_ca_cert, not both')
        elif parent is not None:
            chain_pem = cert + parent._chain_pem
            verify_chain = cert + parent._verify_chain
        elif parent_ca_cert is not None:
            chain_pem = cert
            verify_chain = cert + parent_ca_cert
        else:
            raise ValueError('Either parent or parent_ca_cert must be provided')

        if cert_chain is None:
            cert_chain = chain_pem

        openssl_cli = _openssl_cli or OpenSSLCLI()
        obj = super().__new__(cls, cert=cert, key=key, key_password=key_password, cert_chain=cert_chain, serial=serial)
        obj._openssl_cli = openssl_cli
        obj._chain_pem = chain_pem
        obj._verify_chain = verify_chain
        return obj


# Backward-compatible alias
CA = RootCA
