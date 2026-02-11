"""
Tests for the CA API.
"""

import re
import subprocess

from simple_ca import CA, CKP


def _check_pem_cert(cert):
    assert isinstance(cert, str)
    assert '-----BEGIN CERTIFICATE-----' in cert


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


def test_init_ca():
    ca = CA.init_ca(org='ACME')
    _check_ckp(ca)


def test_init_ca_custom_cn():
    ca = CA.init_ca(org='ACME', cn='My Custom CA')
    _check_ckp(ca)
    out = _openssl_x509_text(ca.cert)
    assert 'My Custom CA' in out


def test_init_ca_is_ca_cert():
    ca = CA.init_ca(org='ACME')
    out = _openssl_x509_text(ca.cert)
    assert 'CA:TRUE' in out


def test_ca_is_instance_of_ckp():
    ca = CA.init_ca(org='ACME')
    assert isinstance(ca, CKP)


def test_ca_tuple_unpacking():
    ca = CA.init_ca(org='ACME')
    cert, key, key_password = ca
    assert cert == ca.cert
    assert key == ca.key
    assert key_password == ca.key_password


def test_ca_indexing():
    ca = CA.init_ca(org='ACME')
    assert ca[0] == ca.cert
    assert ca[1] == ca.key
    assert ca[2] == ca.key_password


def test_create_server_cert():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME')
    _check_ckp(sc)


def test_create_server_cert_with_dc():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', dc='example')
    _check_ckp(sc)
    out = _openssl_x509_text(sc.cert)
    assert 'example' in out


def test_server_cert_is_not_ca():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME')
    out = _openssl_x509_text(sc.cert)
    assert 'CA:FALSE' in out
    assert 'CA:TRUE' not in out


def test_server_cert_verified_by_ca(tmp_path):
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME')
    (tmp_path / 'ca.cert').write_text(ca.cert)
    (tmp_path / 'server.cert').write_text(sc.cert)
    result = subprocess.run(
        ['openssl', 'verify', '-CAfile', str(tmp_path / 'ca.cert'), str(tmp_path / 'server.cert')],
        capture_output=True,
    )
    assert result.returncode == 0


def test_server_cert_returns_ckp():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME')
    assert isinstance(sc, CKP)
    assert not isinstance(sc, CA)


def test_create_server_cert_with_san_dns():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', san=['DNS:localhost'])
    out = _openssl_x509_text(sc.cert)
    assert 'DNS:localhost' in out
    assert 'DNS:DNS:localhost' not in out


def test_create_server_cert_with_san_hostname():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', san=['example.com', '*.example.com'])
    out = _openssl_x509_text(sc.cert)
    assert 'DNS:example.com' in out
    assert 'DNS:*.example.com' in out


def test_create_server_cert_with_san_ip():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', san=['10.0.0.1', 'IP:192.168.1.1'])
    out = _openssl_x509_text(sc.cert)
    assert 'IP Address:10.0.0.1' in out
    assert 'IP Address:192.168.1.1' in out


def test_create_server_cert_with_mixed_san():
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(
        cn='myserver',
        org='ACME',
        san=['DNS:myserver.example.com', '10.0.0.1', 'localhost'],
    )
    out = _openssl_x509_text(sc.cert)
    assert 'DNS:myserver.example.com' in out
    assert 'IP Address:10.0.0.1' in out
    assert 'DNS:localhost' in out


def test_create_multiple_server_certs():
    ca = CA.init_ca(org='ACME')
    sc1 = ca.create_server_cert(cn='server1', org='ACME')
    sc2 = ca.create_server_cert(cn='server2', org='ACME')
    _check_ckp(sc1)
    _check_ckp(sc2)
    assert sc1.cert != sc2.cert
    assert sc1.key != sc2.key


def test_construct_ca_from_existing_pem():
    ca1 = CA.init_ca(org='ACME')
    ca2 = CA(cert=ca1.cert, key=ca1.key, key_password=ca1.key_password)
    sc = ca2.create_server_cert(cn='localhost', org='ACME')
    _check_ckp(sc)
