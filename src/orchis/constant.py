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


class SuiteId(IntEnum):
    RESERVED = 0

    # 1-15 are Basic HIT Suite IDs (upper nibble of 8-bit HIT Suite ID of RFC7401)
    RSA_DSA_SHA256 = 1
    ECDSA_SHA384 = 2
    # ECDSA_LOW_SHA1 = 3  # not supported due to missing curve
    # Unassigned 4
    EDDSA_CSHAKE128 = 5

    # 16 skipped to align with lower nibble of 8-bit HIT Suite ID
    # 17-31 are Extended HIT Suite IDs (lower nibble of 8-bit HIT Suite ID of RFC7401)
    # Unassigned 17-31

    # 32+ are HHIT Suite IDs defined by RFC9374
    # Unassigned 32-253
    PRIVATE_USE_1 = 254
    PRIVATE_USE_2 = 255
