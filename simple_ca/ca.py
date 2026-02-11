from .types import CertKeyPair, DEFAULT_VALIDITY_DAYS
from .openssl_cli import OpenSSLCLI
from .functions.init_ca import InitCA
from .functions.create_intermediate_ca import CreateIntermediateCA
from .functions.create_server_cert import CreateServerCert


class _CABase:
    """
    Base class for Certificate Authorities.

    Provides shared functionality for creating intermediate CAs
    and server certificates. Not intended to be instantiated directly.
    """

    def __init__(
        self, *, cert, key, key_password, cert_chain=None, serial=None, openssl_cli=None, chain_pem='', verify_chain
    ):
        self.cert = cert
        self.key = key
        self.key_password = key_password
        self.cert_chain = cert_chain
        self.serial = serial
        self._openssl_cli = openssl_cli or OpenSSLCLI()
        self._chain_pem = chain_pem
        self._verify_chain = verify_chain

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
        :return: CertKeyPair with cert, key, key_password, cert_chain and serial
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
        return CertKeyPair(cert=x.cert, key=x.key, key_password=x.key_password, cert_chain=cert_chain, serial=x.serial)


class RootCA(_CABase):
    """
    Root Certificate Authority.

    Create a new root CA using the class method :meth:`init_ca`,
    or construct directly from existing PEM data.
    """

    def __init__(
        self,
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
        super().__init__(
            cert=cert,
            key=key,
            key_password=key_password,
            cert_chain=cert_chain,
            serial=serial,
            openssl_cli=_openssl_cli,
            chain_pem=_chain_pem,
            verify_chain=_verify_chain if _verify_chain is not None else cert,
        )

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

    Create a new intermediate CA using :meth:`RootCA.create_intermediate_ca`
    (or :meth:`IntermediateCA.create_intermediate_ca`),
    or construct directly from existing PEM data by providing
    either a ``parent`` CA object or a ``parent_ca_cert`` PEM string.
    """

    def __init__(
        self,
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

        super().__init__(
            cert=cert,
            key=key,
            key_password=key_password,
            cert_chain=cert_chain,
            serial=serial,
            openssl_cli=_openssl_cli,
            chain_pem=chain_pem,
            verify_chain=verify_chain,
        )


# Backward-compatible alias
CA = RootCA
