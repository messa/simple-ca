def extract_serial(openssl_cli, cert_file):
    """Extract certificate serial number (hex string) from a cert file."""
    out = openssl_cli('x509', '-noout', '-serial', '-in', cert_file)
    return out.strip().split('=', 1)[1]
