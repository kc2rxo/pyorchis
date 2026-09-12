from ipaddress import IPv6Address
from typing import Self, Any

from orchis.constant import HipSuiteId, HiAlgorithm
from orchis.crypto import dump_cose_key, dump_jwk, dump_key, OrchisFormat, construct_ip6, OrchisKeyCurve, \
    OrchisKeySize, generate, OrchisKeyAlgorithm, load_cose_key, load_key_id, load_jwk, load_key, suite_id_from_key
from src.orchis.constant import Prefix
from src.orchis.crypto import OrchisKey, construct_host_identity, OrchisAlgorithm


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
    def hi_algorithm(self) -> HiAlgorithm:
        return construct_host_identity(self.public_key)[1]

    @property
    def host_identity(self) -> bytes:
        """
        Returns:
            Host Identity field of the RFC7401 HOST_ID parameter
        """
        return construct_host_identity(self.public_key)[0]

    @property
    def suite_id(self) -> HipSuiteId:
        return suite_id_from_key(self.public_key, prefix=Prefix.from_ip(self.ip))

    @property
    def arpa(self) -> str:
        """
        Returns:
            str IPv6 reverse pointer
        """
        return self.ip.reverse_pointer

    def cose_key(
            self,
            private_key: bool = False,
            rsa_alg: OrchisAlgorithm = 'PS256',
            serialize: bool = False
    ) -> bytes | dict[int, Any]:
        """
        Generates a COSE Key for use with COSE applications.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256
            serialize: bool, default=True

        Returns:
            CBOR encoded COSE Key or COSE Key dict
        """
        return dump_cose_key(
            self.key if private_key else self.public_key,
            bytes.fromhex('D83650') + self.ip.packed,  # set Key ID to Tag 54 w/IP6 = 0xD83650
            rsa_alg,
            serialize
        )

    def jwk(
            self,
            private_key: bool = False,
            rsa_alg: OrchisAlgorithm = 'PS256',
            serialize: bool = False
    ) -> str | dict[str, Any]:
        """
        Generates a JSON Web Key for use with JOSE applications.

        Args:
            private_key: flag to include private key, default=False
            rsa_alg: selection for RSA algorithm, default=PS256
            serialize: bool, default=True

        Returns:
            str encoded JWK or JWK dict
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
            fmt: OrchisFormat = 'PEM',
            password: bytes | None = None
    ) -> bytes | str:
        """
        Exports Orchid instance as PEM data.

        Args:
            private_key: flag to include private key, default=False
            fmt: instance OrchisFormats to encode to, default='PEM'
            password: password in bytes for encryption, default=None

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
        return self.ip == construct_ip6(
            self.key.public_key(),
            _prefix,
            _info,
        )

    @classmethod
    def host_identity_tag(
            cls,
            alg: OrchisKeyAlgorithm,
            dsa: OrchisKeySize = 2048,
            rsa: OrchisKeySize = 2048,
            curve: OrchisKeyCurve = 'Ed25519'
    ) -> Self:
        """
        Generates a Host Identity Tag (HIT) per RFC7401.

        Args:
            alg: instance of OrchisAlgorithm
            dsa: OrchisKeySize, DSA key size in bits, default=2048
            rsa: OrchisKeySize, RSA key size in bits, default=2048
            curve: instance of OrchisKeyCurve, default Ed25519

        Returns:
            Instance of Orchid with HIT
        """
        _orchid = cls()
        _orchid.key = generate(alg, rsa, dsa, curve)
        _orchid.ip = construct_ip6(_orchid.key.public_key(), Prefix.HIT)
        return _orchid


    @classmethod
    def drip_entity_tag(
            cls,
            raa: int,
            hda: int,
            alg: OrchisKeyAlgorithm,
            dsa: OrchisKeySize = 2048,
            rsa: OrchisKeySize = 2048,
            curve: OrchisKeyCurve = 'Ed25519'
    ) -> Self:
        """
        Generates a DRIP Entity Tag (DRIP) per RFC9374.

        Args:
            raa: value for Registered Assigning Authority of HID
            hda: value for HHIT Domain Authority if HID
            alg: instance of OrchisAlgorithm
            dsa: OrchisKeySize, DSA key size in bits, default=2048
            rsa: OrchisKeySize, RSA key size in bits, default=2048
            curve: instance of OrchisKeyCurve, default Ed25519

        Returns:
            Instance of Orchid with DET
        """
        _orchid = cls()
        _orchid.key = generate(alg, rsa, dsa, curve)
        _orchid.ip = construct_ip6(
            _orchid.key.public_key(),
            Prefix.DET,
            (raa << 14 | hda).to_bytes(4),
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
            cose_key: CBOR encoded COSE Key
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
        Loads an instance Orchid from a JSON Web Key.

        Args:
            jwk: str encoded JSON Web Key
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
            prefix: Prefix = Prefix.HIT,
            info: bytes | None = None,
    ) -> Self:
        """
        Loads a PEM file and instantiates an Orchid instance using data.

        Args:
            pem_data: bytes of PEM data
            password: optional PEM decryption password, default=None
            prefix: optional Prefix to use if no Key ID, default=Prefix.HIT
            info: optional additional info to use if no Key ID, default=None

        Returns:
            Instance of Orchid loaded through PEM data
        """
        _orchid = cls()
        _orchid.key = load_key(pem_data, password)
        _orchid.ip = load_key_id(None, _orchid.key.public_key(), prefix, info)
        return _orchid

    def __str__(self) -> str:
        return (
            f"IPv6 (ORCHID): {self.ip.exploded} / {self.ip}\n"
            f"Public Key (HI): {self.host_identity.hex()}"
        )
