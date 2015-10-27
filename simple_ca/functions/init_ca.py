import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent


logger = logging.getLogger(__name__)


class InitCA:
    '''
    This class API may change (non-backward-compatible) between minor versions.
    '''

    def __init__(self, openssl_cli):
        self.logger = logger
        self.openssl_cli = openssl_cli

    def run(self, org, cn):
        with TemporaryDirectory(prefix='simple_ca.') as temp_dir:
            temp_dir = Path(temp_dir)
            self._conf_file = temp_dir / 'openssl-ca.conf'
            self._key_file = temp_dir / 'ca.key'
            self._key_password_file = temp_dir / 'ca.key.password'
            self._cert_file = temp_dir / 'ca.cert'
            self._create_cfg()
            self._create_key()
            self._create_cert(org=org, cn=cn)
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
                0.organizationName     = Organization Name
                organizationalUnitName = Organizational Unit Name
                0.DC                   = Domain Component
                commonName             = Common Name
                [v3_ca]
                subjectKeyIdentifier   = hash
                authorityKeyIdentifier = keyid:always,issuer
                basicConstraints       = critical, CA:true
                keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
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

    def _create_cert(self, org, cn):
        assert self._conf_file.is_file()
        assert self._key_file.is_file()
        assert self._key_password_file.is_file()
        assert not self._cert_file.is_file()
        assert org
        assert cn
        self.openssl_cli(
            'req',
            '-config', self._conf_file,
            '-new',
            '-x509',
            '-days', 10000,
            '-key', self._key_file,
            '-passin', 'file:' + str(self._key_password_file),
            '-out', self._cert_file,
            '-extensions', 'v3_ca',
            '-subj', '/O={org}/CN={cn}'.format(org=org, cn=cn))
        assert self._cert_file.is_file()
        # verify CA certificate
        out = self.openssl_cli(
            'x509',
            '-noout',
            '-text',
            '-in', self._cert_file)
        for line in out.splitlines():
            self.logger.debug('Generated CA cert: %s', line.rstrip())
        assert 'CA:TRUE' in out
        assert 'CA:FALSE' not in out
        assert 'Certificate Sign' in out
        assert 'CRL Sign' in out
        assert 'SSL Client' not in out
        assert 'SSL Server' not in out
