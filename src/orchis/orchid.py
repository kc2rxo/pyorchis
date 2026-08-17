from ipaddress import IPv6Address
from typing import Self, Any

from orchis.crypto import dump_cose_key, dump_jwk, dump_key, OrchisFormats, construct_ip, OrchisKeyCurve, OrchisKeySize, \
    generate, OrchisAlgorithm, load_cose_key, load_key_id, load_jwk, load_key
from src.orchis.constant import SuiteId, ContextId, Prefix
from src.orchis.crypto import OrchisKey, construct_host_identity, suite_id_from_public_key_alg, OrchisRsaAlgorithms


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
    key: OrchisKey
    ip: IPv6Address

    @property
    def public_key(self) -> OrchisKey:
        return self.key.public_key()

    @property
    def has_private(self) -> bool:
        return self.key.has_private()

    @property
    def private_key(self) -> OrchisKey | None:
        return self.key if self.has_private else None

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
        return suite_id_from_public_key_alg(self.public_key)

    def cose_key(
            self,
            private_key: bool = False,
            rsa_alg: OrchisRsaAlgorithms = 'PS256',
            serialize: bool = False
    ) -> bytes | dict[int, Any]:
        """
        Generates a COSE Key for use with COSE applications, specifically the cwt package.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256
            serialize: bool, default=True

        Returns:
            bytes
        """
        return dump_cose_key(
            self.key if private_key else self.public_key,
            bytes.fromhex('D83650') + self.ip.packed, # set Key ID to Tag 54 w/IP6 = 0xD83650
            rsa_alg,
            serialize
        )

    def jwk(
            self,
            private_key: bool = False,
            rsa_alg: OrchisRsaAlgorithms = 'PS256',
            serialize: bool = False
    ) -> str | dict[str, Any]:
        """
        Generates a JSON Web Key for use with JOSE applications, specifically the jwcrypto package.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256
            serialize: bool, default=True

        Returns:
            str
        """
        return dump_jwk(
            self.key if private_key else self.public_key,
            self.ip.compressed,
            rsa_alg,
            serialize
        )

    def dump(
            self,
            private_key: bool = False,
            fmt: OrchisFormats = 'PEM',
            password: bytes | None = None
    ) -> bytes | str:
        """
        Exports Orchid instance as PEM data.

        Args:
            fmt:
            password: optional password in bytes for encryption

        Returns:
            PEM data as bytes
        """
        return dump_key(self.key if private_key else self.public_key, fmt, password)

    def check_integrity(self) -> bool:
        """
        Performs operation to validate that set public key creates ORCHID.

        Returns:
            bool
        """
        _prefix = Prefix.from_ip(self.ip)
        _info = bytes.fromhex('0' + self.ip.packed.hex()[7:14]) if _prefix == Prefix.DET else None
        return self.ip == construct_ip(
            self.key.public_key(),
            _prefix,
            _info,
            ContextId.RFC7401 if _prefix is Prefix.HIT else ContextId.RFC9374
        )

    @classmethod
    def host_identity_tag(
            cls,
            alg: OrchisAlgorithm,
            dsa: OrchisKeySize = 2048,
            rsa: OrchisKeySize = 2048,
            curve: OrchisKeyCurve = 'Ed25519'
    ) -> Self:
        """
        Generates a Host Identity Tag (HIT) per RFC7401.

        Args:
            hit_suite_id: selection of [HIT] Suite ID


        Returns:
            Instance of Orchid with HIT
        """
        _orchid = cls()
        _orchid.key = generate(alg, rsa, dsa, curve)
        _orchid.ip = construct_ip(_orchid.key.public_key(), Prefix.HIT)
        return _orchid

    @classmethod
    def drip_entity_tag(
            cls,
            raa: int,
            hda: int,
            alg: OrchisAlgorithm,
            dsa: OrchisKeySize = 2048,
            rsa: OrchisKeySize = 2048,
            curve: OrchisKeyCurve = 'Ed25519'
    ) -> Self:
        """
        Generates a DRIP Entity Tag (DRIP) per RFC9374.

        Args:
            raa: value for Registered Assigning Authority of HID
            hda: value for HHIT Domain Authority if HID

        Returns:
            Instance of Orchid with DET
        """
        _orchid = cls()
        _orchid.key = generate(alg, rsa, dsa, curve)
        _orchid.ip = construct_ip(
            _orchid.key.public_key(),
            Prefix.DET,
            (raa << 14 | hda).to_bytes(4),
            ContextId.RFC9374
        )
        return _orchid

    @classmethod
    def import_cose_key(
            cls,
            cose_key: bytes,
            prefix: Prefix = Prefix.HIT,
            info: bytes | None = None
    ) -> Self:
        """
        Loads a COSE Key into an Orchid instance.

        Args:
            cose_key:
            prefix: optional Prefix to use if JWK does not have an ORCHID Key ID, default=Prefix.HIT
            info: optional additional info to use if JWK does not have an ORCHID Key ID, default=None

        Returns:
            Instance of Orchid with COSE Key.
        """
        _orchid = cls()
        _orchid.key, _kid = load_cose_key(cose_key)
        _orchid.ip = load_key_id(_kid, _orchid.key.public_key(), prefix, info)
        return _orchid

    @classmethod
    def import_jwk(
            cls,
            jwk: str,
            prefix: Prefix = Prefix.HIT,
            info: bytes | None = None
    ) -> Self:
        """
        Loads an instance Orchid from a JSON Web Key. This function exports the JWK to PEM then
        calls import_pem to reload into the Orchid instance.

        Args:
            jwk: JSON Web Key as str
            prefix: optional Prefix to use if JWK does not have an ORCHID Key ID, default=Prefix.HIT
            info: optional additional info to use if JWK does not have an ORCHID Key ID, default=None

        Returns:
            Instance of Orchid loaded through JWK
        """
        _orchid = cls()
        _orchid.key, _kid = load_jwk(jwk)
        _orchid.ip = load_key_id(_kid, _orchid.key.public_key(), prefix, info)
        return _orchid

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
        _orchid.key = load_key(pem_data, password)
        _orchid.ip = load_key_id(kid, _orchid.key.public_key(), prefix, info)
        return _orchid

    def __str__(self) -> str:
        return (
            f"IPv6 (ORCHID): {self.ip.exploded} / {self.ip}"
            f"Public Key (HI): {self.host_identity.hex()}"
        )
