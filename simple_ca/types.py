from dataclasses import dataclass

DEFAULT_VALIDITY_DAYS = 10000


@dataclass
class CertKeyPair:
    """Certificate, private key and related data."""

    cert: str
    key: str
    key_password: str
    cert_chain: str | None = None
    serial: str | None = None
