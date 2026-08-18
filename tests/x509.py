import unittest
from datetime import datetime, UTC, timedelta

try:
    from cryptography.x509 import Name
    from src.orchis.x509 import csr, load_der_x509, load_pem_x509, certificate
except ImportError:
    raise ImportError('cryptography module not installed to run tests')

from src.orchis.orchid import Orchid


class X509Test(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer: Orchid = Orchid.host_identity_tag('EdDSA', curve='Ed25519')
        self.subject: Orchid = Orchid.host_identity_tag('EdDSA', curve='Ed25519')

    def test_csr_generate(self):
        _ = csr(self.subject, Name([]), True)

    def test_csr_der(self):
        _csr = csr(self.subject, Name([]), True, fmt='DER')
        _ = load_der_x509(_csr)

    def test_csr_pem(self):
        _csr = csr(self.subject, Name([]), True, fmt='PEM')
        _ = load_pem_x509(_csr)

    def test_cert_generate(self):
        _ = certificate(self.issuer, self.subject, datetime.now(UTC), datetime.now() + timedelta(hours=1), 20, Name([]))

    def test_cert_der(self):
        _csr = certificate(self.issuer, self.subject, datetime.now(UTC), datetime.now() + timedelta(hours=1), 20, Name([]), fmt='DER')
        _ = load_der_x509(_csr)

    def test_cert_pem(self):
        _csr = certificate(self.issuer, self.subject, datetime.now(UTC), datetime.now() + timedelta(hours=1), 20, Name([]), fmt='PEM')
        _ = load_pem_x509(_csr)


if __name__ == '__main__':
    unittest.main()
