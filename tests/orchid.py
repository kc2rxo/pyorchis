import unittest
from typing import get_args

from src.orchis.constant import SuiteId
from src.orchis.crypto import OrchisRsaKeySizes, OrchisEcdsaCurves, OrchisEddsaCurves
from src.orchis.orchid import Orchid


class MyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.hits = self._generate_hits()
        self.dets = self._generate_dets()

        self.exported_jose = []
        self.exported_cose = []

    def test_export_jose(self):
        for o in self.hits + self.dets:
            self.exported_jose.append(o.jwk().export())
            self.exported_jose.append(o.jwk().export(False))
            self.exported_jose.append(o.jwk(True).export(False))
            self.exported_jose.append(o.jwk(True).export())

    def test_export_cose(self):
        for o in self.hits + self.dets:
            self.exported_jose.append(o.cose_key().to_dict())
            self.exported_jose.append(o.cose_key(True).to_dict())

    def test_import_jose(self):
        for jwk in self.exported_jose:
            _new = Orchid.import_jwk(jwk)
            self.assertTrue(_new.check_integrity(), f"{_new}")

    @staticmethod
    def _generate_hits() -> list[Orchid]:
        # 2001:002X::
        rsa = [
            Orchid.host_identity_tag(SuiteId.RSA_DSA_SHA256, rsa_key_size=size) for size in get_args(OrchisRsaKeySizes)
        ]
        ecdsa = [
            Orchid.host_identity_tag(SuiteId.ECDSA_SHA384, ecdsa_curve=curve) for curve in get_args(OrchisEcdsaCurves)
        ]
        eddsa = [
            Orchid.host_identity_tag(SuiteId.EDDSA_CSHAKE128, eddsa_curve=curve) for curve in get_args(OrchisEddsaCurves)
        ]
        return rsa + ecdsa + eddsa

    @staticmethod
    def _generate_dets() -> list[Orchid]:
        # 2001:0030:0280:0A:XX::
        rsa = [
            Orchid.drip_entity_tag(10, 10, SuiteId.RSA_DSA_SHA256, rsa_key_size=size) for size in get_args(OrchisRsaKeySizes)]
        ecdsa = [
            Orchid.drip_entity_tag(10, 10, SuiteId.ECDSA_SHA384, ecdsa_curve=curve) for curve in get_args(OrchisEcdsaCurves)]
        eddsa = [
            Orchid.drip_entity_tag(10, 10, SuiteId.EDDSA_CSHAKE128, eddsa_curve=curve) for curve in get_args(OrchisEddsaCurves)]
        return rsa + ecdsa + eddsa


if __name__ == '__main__':
    unittest.main()
