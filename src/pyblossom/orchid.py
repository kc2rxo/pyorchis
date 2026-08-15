from ipaddress import IPv6Address
from secrets import token_bytes, randbelow
from typing import Self, Literal

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cwt import COSEKey
from cwt.cose_key_interface import COSEKeyInterface
from jwcrypto.jwk import JWK

from src.pyblossom.constant import SuiteId, ContextId, Prefix
from src.pyblossom.crypto import (
    OrchidPrivateKeyAlgorithms,
    OrchidPublicKeyAlgorithms,
    OrchidDsaRsaKeySizes,
    OrchidRsaAlgorithms,
    OrchidEcdsaCurves,
    OrchidEddsaCurves,
    generate_key_pair,
    construct_host_identity,
    suite_id_by_public_key_alg,
    construct_ip,
    load_pem_key
)


class Orchid:
    """General ORCHID container.

    Supports both HIT (RFC7401) and DET (RFC9374) identifiers.
    Functions to export keys for COSE and JOSE applications.
    Import of JWKs from JOSE and PEM from legacy applications.

    Attributes:
        x: A public key
        d: An optional private key
        ip: An IPv6 address instance loaded with an ORCHID
    """
    x: OrchidPublicKeyAlgorithms
    d: OrchidPrivateKeyAlgorithms | None
    ip: IPv6Address

    @property
    def public_key(self) -> OrchidPublicKeyAlgorithms:
        return self.x

    @property
    def has_private(self) -> bool:
        return self.d is not None

    @property
    def private_key(self) -> OrchidPrivateKeyAlgorithms | None:
        return self.d

    @property
    def host_identity(self) -> bytes:
        """
        Returns:
            Bytes of Host Identity field of the RFC7401 HOST_ID parameter
        """
        return construct_host_identity(self.public_key)

    @property
    def domain_identifier(self) -> str:
        """
        Returns:
            IPv6 reverse pointer of type str FQDN when a DET, otherwise ''
        """
        return self.ip.reverse_pointer if Prefix.from_ip(self.ip) == Prefix.DET else ''

    @property
    def suite_id(self) -> SuiteId:
        return suite_id_by_public_key_alg(self.public_key)

    def cose_key(
            self,
            private_key: bool = False,
            rsa_alg: OrchidRsaAlgorithms = 'PS256',
    ) -> COSEKeyInterface:
        """
        Generates a COSE Key for use with COSE applications, specifically the cwt package.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256

        Returns:
            cwt.COSEKeyInterface instance
        """
        _cose_key = COSEKey.from_jwk(self.jwk(private_key, rsa_alg)).to_dict()
        # set kid as bytes of ip instead of bytes(str) that was auto-generated from jwk
        _cose_key[2] = bytes.fromhex('D83650') + self.ip.packed  # Tag 54=0xD83650
        return COSEKey.new(_cose_key)

    def jwk(
            self,
            private_key: bool = False,
            rsa_alg: OrchidRsaAlgorithms = 'PS256',
    ) -> JWK:
        """
        Generates a JSON Web Key for use with JOSE applications, specifically the jwcrypto package.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256

        Returns:
            jwcrypto.JWK instance
        """
        _jwk = JWK.from_pyca(self.d) if private_key and self.d else JWK.from_pyca(self.x)
        _jwk['kid'] = self.ip.compressed  # todo: exploded?
        if isinstance(self.x, RSAPublicKey): _jwk['alg'] = rsa_alg  # set the 'alg' as it is required for COSE
        return _jwk

    def check_integrity(self) -> bool:
        """
        Performs operation to validate that set public key creates ORCHID.

        Returns:
            bool
        """
        _prefix = Prefix.from_ip(self.ip)
        _info = bytes.fromhex(self.ip.packed.hex()[7:14]) if _prefix == Prefix.DET else None
        return self.ip == construct_ip(
            self.x,
            _prefix,
            _info,
            ContextId.RFC7401 if _prefix is Prefix.HIT else ContextId.RFC9374
        )

    @classmethod
    def host_identity_tag(
            cls,
            hit_suite_id: SuiteId,
            rsa_key_size: OrchidDsaRsaKeySizes = 2048,
            ecdsa_curve: OrchidEcdsaCurves = 'P-256',
            eddsa_curve: OrchidEddsaCurves = 'Ed25519',
    ) -> Self:
        """
        Generates a Host Identity Tag (HIT) per RFC7401.

        Args:
            hit_suite_id: selection of [HIT] Suite ID
            rsa_key_size: preferred RSA key size (2048, 4069, 8192), default=2048
            ecdsa_curve: preferred ECDSA curve (NIST P-256, NIST P-384), default=P-256
            eddsa_curve: preferred EdDSA curve (Ed25519, Ed448), default=Ed25519

        Returns:
            Instance of Orchid
        """
        _orchid = cls()
        _orchid.x, _orchid.d = generate_key_pair(hit_suite_id, rsa_key_size, ecdsa_curve, eddsa_curve)
        _orchid.ip = construct_ip(_orchid.x, Prefix.HIT)
        return _orchid

    @classmethod
    def drip_entity_tag(
            cls,
            raa: int,
            hda: int,
            hhit_suite_id: SuiteId,
            rsa_key_size: OrchidDsaRsaKeySizes = 2048,
            ecdsa_curve: OrchidEcdsaCurves = 'P-256',
            eddsa_curve: OrchidEddsaCurves = 'Ed25519'
    ) -> Self:
        """
        Generates a DRIP Entity Tag (DRIP) per RFC9374.

        Args:
            raa: value for Registered Assigning Authority of HID
            hda: value for HHIT Domain Authority if HID
            hhit_suite_id: selection of [HHIT] Suite ID
            rsa_key_size: preferred RSA key size (2048, 4069, 8192), default=2048
            ecdsa_curve: preferred ECDSA curve (NIST P-256, NIST P-384), default=P-256
            eddsa_curve: preferred EdDSA curve (Ed25519, Ed448), default=Ed25519

        Returns:
            Instance of Orchid
        """
        _orchid = cls()
        _orchid.x, _orchid.d = generate_key_pair(hhit_suite_id, rsa_key_size, ecdsa_curve, eddsa_curve)
        _orchid.ip = construct_ip(_orchid.x, Prefix.DET, (raa << 14 | hda).to_bytes(4), ContextId.RFC9374)
        return _orchid

    @classmethod
    def import_jwk(
            cls,
            jwk: str,
            prefix: Prefix = Prefix.HIT,
            info: bytes | None = None,
    ) -> Self:
        """
        Loads an instance Orchid from a JSON Web Key. This function calls import_pem to load
        the key properly.

        Args:
            jwk: JSON Web Key as str
            prefix: optional Prefix to use if JWK does not have an ORCHID Key ID, default=Prefix.HIT
            info: optional additional info to use if JWK does not have an ORCHID Key ID, default=None

        Returns:
            Instance of Orchid loaded through JWK
        """
        _jwk = JWK.from_json(jwk)
        _password: bytes | None = token_bytes(randbelow(100)) if _jwk.has_private else None
        return cls.import_pem(
            _jwk.export_to_pem(Literal[True] if _jwk.has_private else False, _password),
            _password,
            _jwk['kid'],
            prefix,
            info
        )

    @classmethod
    def import_pem(
            cls,
            pem_data: bytes,
            password: bytes | None = None,
            kid: str = '',
            prefix: Prefix = Prefix.HIT,
            info: bytes | None = None,
    ) -> Self:
        """
        Loads a PEM file and instantiates a Orchid instance using data.

        Args:
            pem_data: bytes of PEM data
            password: optional PEM decryption password, default=None
            kid: optional ORCHID Key ID from COSE Key or JWK, default=''
            prefix: optional Prefix to use if JWK does not have an ORCHID Key ID, default=Prefix.HIT
            info: optional additional info to use if JWK does not have an ORCHID Key ID, default=None

        Returns:
            Instance of Orchid loaded through PEM data
        """
        _orchid = cls()
        _orchid.x, _orchid.d = load_pem_key(pem_data, password)
        try:
            _orchid.ip = IPv6Address(kid)
        except ValueError:
            _orchid.ip = construct_ip(
                _orchid.x,
                prefix,
                info,
                ContextId.RFC7401 if prefix is Prefix.HIT else ContextId.RFC9374
            )
        return _orchid

    def __str__(self) -> str:
        return (
            f"IPv6 (ORCHID): {self.ip.exploded} / {self.ip}"
            f"Public Key (HI): {self.host_identity.hex()}"
        )
