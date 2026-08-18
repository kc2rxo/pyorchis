import unittest
from typing import get_args

from orchis.crypto import OrchisKeySize
from src.orchis.orchid import Orchid


class OrchidTest(unittest.TestCase):
    def setUp(self) -> None:
        self.hits = self._generate_hits()
        self.dets = self._generate_dets()

        self.exported_jose = []
        self.exported_cose = []
        self.exported_pem = []

    def test_cose(self):
        self._export_cose()
        for cose_key in self.exported_cose:
            _new = Orchid.import_cose_key(cose_key)
            self.assertTrue(_new.check_integrity(), f"{_new}")

    def test_jose(self):
        self._export_jose()
        for jwk in self.exported_jose:
            _new = Orchid.import_jwk(jwk)
            self.assertTrue(_new.check_integrity(), f"{_new}")

    def test_pem(self):
        self._export_pem()
        for pem in self.exported_pem:
            _new = Orchid.import_pem(pem)
            self.assertTrue(_new.check_integrity(), f"{_new}")

    def _export_jose(self):
        for o in self.hits + self.dets:
            self.exported_jose.append(o.jwk(serialize=True))
            self.exported_jose.append(o.jwk(True, serialize=True))

    def _export_cose(self):
        for o in self.hits + self.dets:
            self.exported_cose.append(o.cose_key(serialize=True))
            self.exported_cose.append(o.cose_key(True, serialize=True))

    def _export_pem(self):
        for o in self.hits + self.dets:
            self.exported_pem.append(o.dump())
            self.exported_pem.append(o.dump(True))

    @staticmethod
    def _generate_hits() -> list[Orchid]:
        # 2001:002X::
        rsa = [Orchid.host_identity_tag('RSA', rsa=size) for size in get_args(OrchisKeySize)]
        ecdsa = [Orchid.host_identity_tag('ECDSA', curve=curve) for curve in ('P-256', 'P-384')]
        eddsa = [Orchid.host_identity_tag('EdDSA', curve=curve) for curve in ('Ed25519', 'Ed448')]
        return rsa + ecdsa + eddsa

    @staticmethod
    def _generate_dets() -> list[Orchid]:
        # 2001:0030:0280:0A:XX::
        rsa = [Orchid.drip_entity_tag(10, 10, 'RSA', rsa=size) for size in get_args(OrchisKeySize)]
        ecdsa = [Orchid.drip_entity_tag(10, 10, 'ECDSA', curve=curve) for curve in ('P-256', 'P-384')]
        eddsa = [Orchid.drip_entity_tag(10, 10, 'EdDSA', curve=curve) for curve in ('Ed25519', 'Ed448')]
        return rsa + ecdsa + eddsa


if __name__ == '__main__':
    unittest.main()
