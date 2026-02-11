from logging import getLogger
from pathlib import Path
from time import time_ns
from tempfile import TemporaryDirectory
from textwrap import dedent


logger = getLogger(__name__)


class CreateIntermediateCA:
    """
    Create an intermediate CA certificate signed by a parent CA.

    This class API may change (non-backward-compatible) between minor versions.
    """

    def __init__(self, openssl_cli, ca_cert, ca_key, ca_key_password, ca_verify_chain=None):
        self.logger = logger
        self.openssl_cli = openssl_cli
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_key_password = ca_key_password
        self.ca_verify_chain = ca_verify_chain

    def run(self, org, cn):
        with TemporaryDirectory(prefix='simple_ca.') as temp_dir:
            temp_dir = Path(temp_dir)
            self._conf_file = temp_dir / 'openssl.conf'
            self._ca_key_file = temp_dir / 'ca.key'
            self._ca_key_password_file = temp_dir / 'ca.key.password'
            self._ca_cert_file = temp_dir / 'ca.cert'
            self._ca_key_file.write_text(self.ca_key)
            self._ca_key_password_file.write_text(self.ca_key_password)
            self._ca_cert_file.write_text(self.ca_cert)
            if self.ca_verify_chain:
                self._ca_verify_file = temp_dir / 'ca_bundle.cert'
                self._ca_verify_file.write_text(self.ca_verify_chain)
            else:
                self._ca_verify_file = self._ca_cert_file
            self._key_file = temp_dir / 'intermediate.key'
            self._key_password_file = temp_dir / 'intermediate.key.password'
            self._csr_file = temp_dir / 'intermediate.csr'
            self._cert_file = temp_dir / 'intermediate.cert'
            self._create_cfg()
            self._create_key()
            self._create_csr(org=org, cn=cn)
            self._create_cert()
            assert self.key_password
            self.key = self._key_file.read_text()
            self.cert = self._cert_file.read_text()

    def _create_cfg(self):
        assert not self._conf_file.is_file()
        self._conf_file.write_text(
            dedent("""
                [req]
                default_bits        = 4096
                distinguished_name  = req_distinguished_name
                string_mask         = utf8only
                default_md          = sha256
                [req_distinguished_name]
                0.organizationName     = Organization Name
                commonName             = Common Name
                [v3_intermediate_ca]
                subjectKeyIdentifier   = hash
                authorityKeyIdentifier = keyid:always,issuer
                basicConstraints       = critical, CA:true, pathlen:0
                keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
            """)
        )

    def _create_key(self):
        assert not self._key_file.is_file()
        assert not self._key_password_file.is_file()
        out = self.openssl_cli('rand', '-base64', 15)
        self.key_password = out.strip()
        assert len(self.key_password) == 15 / 3 * 4
        self._key_password_file.write_text(self.key_password)
        self.openssl_cli(
            'genrsa', '-aes256', '-out', self._key_file, '-passout', 'file:' + str(self._key_password_file), 4096
        )

    def _create_csr(self, org, cn):
        assert self._conf_file.is_file()
        assert self._key_file.is_file()
        assert self._key_password_file.is_file()
        assert not self._csr_file.is_file()
        self.openssl_cli(
            'req',
            '-config',
            self._conf_file,
            '-new',
            '-key',
            self._key_file,
            '-passin',
            'file:' + str(self._key_password_file),
            '-out',
            self._csr_file,
            '-subj',
            '/O={org}/CN={cn}'.format(org=org, cn=cn),
        )
        assert self._csr_file.is_file()

    def _create_cert(self):
        assert self._conf_file.is_file()
        assert self._ca_cert_file.is_file()
        assert self._ca_key_file.is_file()
        assert self._ca_key_password_file.is_file()
        assert self._csr_file.is_file()
        assert not self._cert_file.is_file()
        self.openssl_cli(
            'x509',
            '-req',
            '-extfile',
            self._conf_file,
            '-days',
            10000,
            '-in',
            self._csr_file,
            '-CA',
            self._ca_cert_file,
            '-CAkey',
            self._ca_key_file,
            '-passin',
            'file:' + str(self._ca_key_password_file),
            '-set_serial',
            time_ns() // 1000,
            '-out',
            self._cert_file,
            '-extensions',
            'v3_intermediate_ca',
        )
        assert self._cert_file.is_file()
        # verify intermediate CA certificate
        out = self.openssl_cli('x509', '-noout', '-text', '-in', self._cert_file)
        for line in out.splitlines():
            self.logger.debug('Generated intermediate CA cert: %s', line.rstrip())
        assert 'CA:TRUE' in out
        assert 'CA:FALSE' not in out
        assert 'Certificate Sign' in out
        assert 'CRL Sign' in out
        assert 'SSL Client' not in out
        assert 'SSL Server' not in out
        out = self.openssl_cli('verify', '-CAfile', self._ca_verify_file, self._cert_file)
        assert 'OK' in out
