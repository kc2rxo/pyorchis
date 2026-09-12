from enum import Enum, IntEnum
from ipaddress import IPv6Address


class ContextId(Enum):
    RFC7401 = bytes.fromhex("F0EFF02FBFF43D0FE7930C3C6E6174EA")
    RFC9374 = bytes.fromhex("00B5A69C795DF5D5F0087F56843F2C40")


class Prefix(Enum):
    HIT = bytes.fromhex("20010020")  # 2001:20/28
    DET = bytes.fromhex("20010030")  # 2001:30/28

    @classmethod
    def from_ip(cls, ip: IPv6Address) -> 'Prefix':
        if ip.packed.hex().startswith(cls.HIT.value.hex()[:-1]):
            return cls.HIT
        elif ip.packed.hex().startswith(cls.DET.value.hex()[:-1]):
            return cls.DET
        else:
            raise ValueError("unknown IPv6 prefix")


class HiAlgorithm(IntEnum):
    RESERVED = 0
    NULL_ENCRYPT = 1
    # Unassigned = 2
    DSA = 3
    # Unassigned = 4
    RSA = 5
    # Unassigned = 6
    ECDSA = 7
    # Unassigned = 8
    ECDSA_LOW = 9
    # Unassigned = 10
    # Unassigned = 11
    # Unassigned = 12
    EDDSA = 13
    # Unassigned = 14 - 65535


class HipSuiteId(IntEnum):
    RESERVED = 0

    # 0x01 - 0x0F: Extended HIT Suite ID Mapping; draft-atw-orchid-v3, Appendix C
    # Unassigned = 1
    ECDSA_P256_SHA384 = 2
    ECDSA_LOW_SECP160R1_SHA1 = 3  # not supported, missing curve
    # Unassigned = 4
    EDDSA_25519_CSHAKE128 = 5
    # Unassigned = 6 - 15

    # 0x[1-F]0: Basic HIT Suite ID Mapping; draft-atw-orchid-v3, Appendix C
    RSA_DSA_SHA256 = 16
    ECDSA_SHA384 = 32
    ECDSA_LOW_SHA1 = 48  # not supported, missing curve
    # Unassigned = 64
    EDDSA_CSHAKE128 = 80
    # Unassigned = 96
    # Unassigned = 112
    # Unassigned = 128
    # Unassigned = 144
    # Unassigned = 160
    # Unassigned = 176
    # Unassigned = 192
    # Unassigned = 208
    # Unassigned = 224
    # Unassigned = 240

    # DET Suite ID Blocks; draft-atw-orchid-v3, Appendix C
    # 0x11 - 0x1F
    # 0x21 - 0x2F
    ECDSA_P384_SHA384 = 33
    # ECDSA_P256_CSHAKE128 = 34
    # ECDSA_P384_CSHAKE256 = 35
    # 0x31 - 0x3F
    # 0x41 - 0x4F
    # 0x51 - 0x5F
    EDDSA_25519PH_CSHAKE128 = 81
    EDDSA_448_CSHAKE256 = 82
    EDDSA_448PH_CSHAKE256 = 83
    # 0x61 - 0x6F
    # 0x71 - 0x7F
    # 0x81 - 0x8F
    # 0x91 - 0x9F
    # 0xA1 - 0xAF
    # 0xB1 - 0xBF
    # 0xC1 - 0xCF
    # 0xD1 - 0xDF
    # 0xE1 - 0xEF
    # 0xF1 - 0xFF
    PRIVATE_USE_1 = 254
    PRIVATE_USE_2 = 255


class NewHipSuiteId(IntEnum):
    # draft-atw-orchid-v3, Section 3.1.1, Section 4.4 & Section 5.2
    RESERVED = 0  # 0x80

    # 0x81 - 0x8F (1 - 15): Extended
    ECDSA_P256_SHA384 = 2
    ECDSA_LOW_SECP160R1_SHA1 = 3
    EDDSA_25519_CSHAKE128 = 5
    # 0x90/0x1 (16): Basic, 0x91 - 0x9F (17 - 31): Extended
    RSA_DSA_SHA256 = 16
    # 0xA0/0x2 (32): Basic, - 0xAF (33 - 47): Extended
    ECDSA_SHA384 = 32
    ECDSA_P384_SHA384 = 33
    # 0xB0/0x3 (48): Basic, 0x0B1 - 0xBF (49 - 63): Extended
    ECDSA_LOW_SHA1 = 48
    # 0xC0/0x4 (64): Basic, 0xC1 - 0xCF (65 - 79): Extended
    # 0xD0/0x5 (80): Basic, 0xD1 - 0xDF (81 - 95): Extended
    EDDSA_CSHAKE128 = 80
    EDDSA_25519PH_CSHAKE128 = 81
    EDDSA_448_CSHAKE256 = 82
    EDDSA_448PH_CSHAKE256 = 83
    # 0xE0/0x6 (96): Basic, 0xE1 - 0xEF (97 - 111): Extended
    # 0xF0/0x7 (112): Basic, 0xF1 - 0xFF (113 - 127): Extended
    PRIVATE_USE_1 = 126
    PRIVATE_USE_2 = 127

    def oga_id(self, extended: bool = False) -> bytes:
        _v = (self | 0x80) if extended else (self & 0b01110000)
        if not self._is_valid(_v): raise ValueError(f"invalid {'extended' if extended else 'basic'} oga id")
        return _v.to_bytes(1)

    @classmethod
    def hit_suite_ids(cls) -> tuple:
        return cls.RSA_DSA_SHA256, cls.ECDSA_SHA384, cls.ECDSA_LOW_SHA1, None, cls.EDDSA_CSHAKE128, None, None

    @classmethod
    def _is_valid(cls, value: int) -> bool:
        return value in cls._value2member_map_
