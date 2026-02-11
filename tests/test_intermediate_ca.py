"""
Tests for the IntermediateCA API — creating intermediate CAs,
reconstructing from existing PEM data, and signing server certs.
"""

import re
import subprocess
from datetime import datetime

from pytest import raises

from simple_ca import CA, IntermediateCA, RootCA


def _check_pem_cert(cert):
    assert isinstance(cert, str)
    assert '-----BEGIN CERTIFICATE-----' in cert
    assert '-----END CERTIFICATE-----' in cert


def _check_pem_key(key):
    assert isinstance(key, str)
    assert re.match(r'-----BEGIN (ENCRYPTED|RSA) PRIVATE KEY-----', key)


def _check_ckp(ckp):
    _check_pem_cert(ckp.cert)
    _check_pem_key(ckp.key)
    assert isinstance(ckp.key_password, str)
    assert len(ckp.key_password) > 10


def _openssl_x509_text(cert_pem):
    return subprocess.check_output(
        ['openssl', 'x509', '-noout', '-text'],
        input=cert_pem.encode(),
    ).decode()


def _get_cert_validity_days(cert_pem):
    """Extract validity period in days from PEM certificate."""
    out = subprocess.check_output(
        ['openssl', 'x509', '-noout', '-startdate', '-enddate'],
        input=cert_pem.encode(),
    ).decode()
    dates = {}
    for line in out.strip().splitlines():
        key, value = line.split('=', 1)
        dates[key] = datetime.strptime(value, '%b %d %H:%M:%S %Y %Z')
    delta = dates['notAfter'] - dates['notBefore']
    return delta.days


# --- RootCA / CA alias ---


def test_root_ca_alias():
    assert CA is RootCA


def test_root_ca_init_ca():
    ca = RootCA.init_ca(org='ACME')
    _check_ckp(ca)
    assert isinstance(ca, RootCA)


# --- Creating intermediate CA ---


def test_create_intermediate_ca():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME', cn='Intermediate CA')
    _check_ckp(inter)
    assert isinstance(inter, IntermediateCA)


def test_intermediate_ca_is_ca_cert():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    out = _openssl_x509_text(inter.cert)
    assert 'CA:TRUE' in out
    assert 'Certificate Sign' in out
    assert 'CRL Sign' in out


def test_intermediate_ca_has_pathlen():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    out = _openssl_x509_text(inter.cert)
    assert 'pathlen:0' in out


def test_intermediate_ca_custom_cn():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME', cn='My Intermediate')
    out = _openssl_x509_text(inter.cert)
    assert 'My Intermediate' in out


def test_intermediate_ca_verified_by_root(tmp_path):
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    (tmp_path / 'root.cert').write_text(root.cert)
    (tmp_path / 'inter.cert').write_text(inter.cert)
    result = subprocess.run(
        ['openssl', 'verify', '-CAfile', str(tmp_path / 'root.cert'), str(tmp_path / 'inter.cert')],
        capture_output=True,
    )
    assert result.returncode == 0


def test_intermediate_ca_cert_chain():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    assert inter.cert_chain is not None
    assert inter.cert in inter.cert_chain
    assert root.cert not in inter.cert_chain


def test_intermediate_ca_custom_validity():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME', days=3650)
    _check_ckp(inter)
    assert _get_cert_validity_days(inter.cert) == 3650


def test_intermediate_ca_has_serial():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    assert inter.serial is not None
    assert isinstance(inter.serial, str)
    assert len(inter.serial) > 0
    int(inter.serial, 16)


# --- Server certs from intermediate CA ---


def test_server_cert_from_intermediate():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    sc = inter.create_server_cert(cn='localhost', org='ACME')
    _check_ckp(sc)
    out = _openssl_x509_text(sc.cert)
    assert 'CA:FALSE' in out


def test_server_cert_from_intermediate_cert_chain():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    sc = inter.create_server_cert(cn='localhost', org='ACME')
    # cert_chain should contain both server cert and intermediate cert
    assert sc.cert in sc.cert_chain
    assert inter.cert in sc.cert_chain
    # but not the root cert
    assert root.cert not in sc.cert_chain


def test_server_cert_from_intermediate_verified(tmp_path):
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    sc = inter.create_server_cert(cn='localhost', org='ACME')
    (tmp_path / 'root.cert').write_text(root.cert)
    (tmp_path / 'inter.cert').write_text(inter.cert)
    (tmp_path / 'server.cert').write_text(sc.cert)
    result = subprocess.run(
        [
            'openssl',
            'verify',
            '-CAfile',
            str(tmp_path / 'root.cert'),
            '-untrusted',
            str(tmp_path / 'inter.cert'),
            str(tmp_path / 'server.cert'),
        ],
        capture_output=True,
    )
    assert result.returncode == 0


def test_server_cert_from_intermediate_with_san():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME')
    sc = inter.create_server_cert(cn='localhost', org='ACME', san=['localhost', '127.0.0.1'])
    out = _openssl_x509_text(sc.cert)
    assert 'DNS:localhost' in out
    assert 'IP Address:127.0.0.1' in out


# --- Reconstructing IntermediateCA from existing PEM data ---


def test_construct_intermediate_ca_from_existing_with_parent():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter_orig = root.create_intermediate_ca(org='ACME', cn='Intermediate CA')
    # Reconstruct from existing PEM data using parent CA object
    inter = IntermediateCA(
        cert=inter_orig.cert,
        key=inter_orig.key,
        key_password=inter_orig.key_password,
        parent=root,
    )
    assert isinstance(inter, IntermediateCA)
    _check_ckp(inter)
    # Should be able to create server certs
    sc = inter.create_server_cert(cn='localhost', org='ACME', san=['localhost'])
    _check_ckp(sc)
    # cert_chain should contain both server cert and intermediate cert
    assert sc.cert in sc.cert_chain
    assert inter.cert in sc.cert_chain


def test_construct_intermediate_ca_from_existing_with_parent_ca_cert():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter_orig = root.create_intermediate_ca(org='ACME', cn='Intermediate CA')
    # Reconstruct from existing PEM data using raw parent cert string
    inter = IntermediateCA(
        cert=inter_orig.cert,
        key=inter_orig.key,
        key_password=inter_orig.key_password,
        parent_ca_cert=root.cert,
    )
    assert isinstance(inter, IntermediateCA)
    _check_ckp(inter)
    sc = inter.create_server_cert(cn='localhost', org='ACME', san=['localhost'])
    _check_ckp(sc)
    assert sc.cert in sc.cert_chain
    assert inter.cert in sc.cert_chain


def test_intermediate_ca_from_existing_server_cert_verified(tmp_path):
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter_orig = root.create_intermediate_ca(org='ACME')
    # Reconstruct intermediate CA from PEM data
    inter = IntermediateCA(
        cert=inter_orig.cert,
        key=inter_orig.key,
        key_password=inter_orig.key_password,
        parent=root,
    )
    sc = inter.create_server_cert(cn='localhost', org='ACME')
    (tmp_path / 'root.cert').write_text(root.cert)
    (tmp_path / 'inter.cert').write_text(inter.cert)
    (tmp_path / 'server.cert').write_text(sc.cert)
    result = subprocess.run(
        [
            'openssl',
            'verify',
            '-CAfile',
            str(tmp_path / 'root.cert'),
            '-untrusted',
            str(tmp_path / 'inter.cert'),
            str(tmp_path / 'server.cert'),
        ],
        capture_output=True,
    )
    assert result.returncode == 0


def test_intermediate_ca_requires_parent():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter_orig = root.create_intermediate_ca(org='ACME')
    with raises(ValueError, match='Either parent or parent_ca_cert must be provided'):
        IntermediateCA(
            cert=inter_orig.cert,
            key=inter_orig.key,
            key_password=inter_orig.key_password,
        )


def test_intermediate_ca_rejects_both_parent_and_parent_ca_cert():
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter_orig = root.create_intermediate_ca(org='ACME')
    with raises(ValueError, match='Specify either parent or parent_ca_cert, not both'):
        IntermediateCA(
            cert=inter_orig.cert,
            key=inter_orig.key,
            key_password=inter_orig.key_password,
            parent=root,
            parent_ca_cert=root.cert,
        )
