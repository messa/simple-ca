from pprint import pprint

from simple_ca import SimpleCA


def test_smoke():
    SimpleCA()


def test_init_ca():
    s = SimpleCA()
    result = s.init_ca(org='ACME')
    assert result.cert
    assert result.key
    assert result.key_password
    assert isinstance(result.cert, str)
    assert isinstance(result.key, str)
    assert isinstance(result.key_password, str)
    assert '-----BEGIN CERTIFICATE-----' in result.cert
    assert '-----BEGIN RSA PRIVATE KEY-----' in result.key
    assert len(result.key_password) > 10


def test_create_server_cert():
    s = SimpleCA()
    ca = s.init_ca(org='ACME')
    # SimpleCA object is stateless, you have to pass CA data again to create server cert
    sc = s.create_server_cert(
        ca_cert=ca.cert, ca_key=ca.key, ca_key_password=ca.key_password,
        cn='localhost', org='ACME', dc='example')
    assert sc.cert
    assert sc.key
    assert sc.key_password
    assert isinstance(sc.cert, str)
    assert isinstance(sc.key, str)
    assert isinstance(sc.key_password, str)
    assert '-----BEGIN CERTIFICATE-----' in sc.cert
    assert '-----BEGIN RSA PRIVATE KEY-----' in sc.key
    assert len(sc.key_password) > 10
