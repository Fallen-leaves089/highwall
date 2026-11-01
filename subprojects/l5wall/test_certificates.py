"""Generate disposable TLS material for L5Wall tests.

The generated files live under ``tests/fixtures`` and are ignored by Git. They
must never be used outside the loopback test suite.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests" / "fixtures"
CERT_FILE = FIXTURES / "test-cert.pem"
KEY_FILE = FIXTURES / "test-key.pem"


def ensure_test_material(directory: Path = FIXTURES) -> tuple[Path, Path]:
    """Create a non-production localhost certificate if it is not present."""
    cert_file = directory / "test-cert.pem"
    key_file = directory / "test-key.pem"
    if cert_file.is_file() and key_file.is_file():
        return cert_file, key_file

    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return cert_file, key_file


if __name__ == "__main__":
    cert_path, key_path = ensure_test_material()
    print(f"disposable test material ready: {cert_path.name}, {key_path.name}")
