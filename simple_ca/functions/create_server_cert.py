import logging
from pathlib import Path
import time
from tempfile import TemporaryDirectory
from textwrap import dedent


logger = logging.getLogger(__name__)


class CreateServerCert:
    '''
    This class API may change (non-backward-compatible) between minor versions.
    '''

    def __init__(self, openssl_cli, ca_cert, ca_key, ca_key_password):
        self.logger = logger
        self.openssl_cli = openssl_cli
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_key_password = ca_key_password

    def run(self, cn, org, dc):
        with TemporaryDirectory(prefix='simple_ca.') as temp_dir:
            temp_dir = Path(temp_dir)
            self._conf_file = temp_dir / 'openssl.conf'
            self._ca_key_file = temp_dir / 'ca.key'
            self._ca_key_password_file = temp_dir / 'ca.key.password'
            self._ca_cert_file = temp_dir / 'ca.cert'
            with self._ca_key_file.open('w') as f:
                f.write(self.ca_key)
            with self._ca_key_password_file.open('w') as f:
                f.write(self.ca_key_password)
            with self._ca_cert_file.open('w') as f:
                f.write(self.ca_cert)
            self._key_file = temp_dir / 'server.key'
            self._key_password_file = temp_dir / 'server.key.password'
            self._csr_file = temp_dir / 'server.csr'
            self._cert_file = temp_dir / 'server.cert'
            self._create_cfg()
            self._create_key()
            self._create_csr(cn=cn, org=org, dc=dc)
            self._create_cert()
            assert self.key_password
            self.key = self._key_file.open().read()
            self.cert = self._cert_file.open().read()

    def _create_cfg(self):
        assert not self._conf_file.is_file()
        with self._conf_file.open('w') as f:
            f.write(dedent('''
                [req]
                default_bits        = 4096
                distinguished_name  = req_distinguished_name
                string_mask         = utf8only
                default_md          = sha256
                [req_distinguished_name]
                0.organizationName              = Organization Name
                organizationalUnitName          = Organizational Unit Name
                0.DC                            = Domain Component
                commonName                      = Common Name
                [v3_server_client]
                basicConstraints        = CA:FALSE
                nsCertType              = server, client
                nsComment               = "OpenSSL Generated Server Certificate"
                subjectKeyIdentifier    = hash
                authorityKeyIdentifier  = keyid,issuer:always
                keyUsage                = critical, nonRepudiation, digitalSignature, keyEncipherment
                extendedKeyUsage        = serverAuth, clientAuth
            '''))

    def _create_key(self):
        assert not self._key_file.is_file()
        assert not self._key_password_file.is_file()
        out = self.openssl_cli('rand', '-base64', 15)
        self.key_password = out.strip()
        assert len(self.key_password) == 15 / 3 * 4
        with self._key_password_file.open('w') as f:
            f.write(self.key_password)
        self.openssl_cli(
            'genrsa',
            '-aes256',
            '-out', self._key_file,
            '-passout', 'file:' + str(self._key_password_file),
            4096)

    def _get_subj(self, cn, org, dc):
        s = '/O=' + org
        s += '/CN=' + cn
        if dc:
            s += '/DC=' + dc
        return s

    def _create_csr(self, cn, org, dc):
        assert self._conf_file.is_file()
        assert self._key_file.is_file()
        assert self._key_password_file.is_file()
        assert not self._csr_file.is_file()
        self.openssl_cli(
            'req',
            '-config', self._conf_file,
            '-new',
            '-key', self._key_file,
            '-passin', 'file:' + str(self._key_password_file),
            '-out', self._csr_file,
            '-subj', self._get_subj(cn=cn, org=org, dc=dc))
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
            '-extfile', self._conf_file,
            '-days', 10000,
            '-in', self._csr_file,
            '-CA', self._ca_cert_file,
            '-CAkey', self._ca_key_file,
            '-passin', 'file:' + str(self._ca_key_password_file),
            '-set_serial', int(time.time() * 1000000),
            '-out', self._cert_file,
            '-extensions', 'v3_server_client')
        assert self._cert_file.is_file()
        # verify CA certificate
        out = self.openssl_cli(
            'x509',
            '-noout',
            '-text',
            '-in', self._cert_file)
        for line in out.splitlines():
            self.logger.debug('Generated server cert: %s', line.rstrip())
        assert 'CA:FALSE' in out
        assert 'CA:TRUE' not in out
        assert 'SSL Client' in out
        assert 'SSL Server' in out
        assert 'Certificate Sign' not in out
        assert 'CRL Sign' not in out
        out = self.openssl_cli(
            'verify',
            '-CAfile', self._ca_cert_file,
            self._cert_file)
        assert 'OK' in out
