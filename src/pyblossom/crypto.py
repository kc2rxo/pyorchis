from ipaddress import IPv6Address
from typing import Literal

from Crypto.Hash import cSHAKE128, SHA256, SHA384
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey, Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from src.pyblossom.constant import ContextId, Prefix, SuiteId


OrchidPublicKeyAlgorithms = Ed448PublicKey | Ed25519PublicKey | RSAPublicKey | EllipticCurvePublicKey
OrchidPrivateKeyAlgorithms = Ed448PrivateKey | Ed25519PrivateKey | RSAPrivateKey | EllipticCurvePrivateKey
OrchidDsaRsaKeySizes = Literal[2048, 4096, 8192]
OrchidRsaAlgorithms = Literal['PS256', 'PS384', 'PS512']
OrchidEcdsaCurves = Literal['P-256', 'P-384']
OrchidEddsaCurves = Literal['Ed448', 'Ed25519']


def suite_id_by_public_key_alg(public: OrchidPublicKeyAlgorithms) -> SuiteId:
    if isinstance(public, RSAPublicKey):
        return SuiteId.RSA_DSA_SHA256
    elif isinstance(public, EllipticCurvePublicKey):
        return SuiteId.ECDSA_SHA384
    elif isinstance(public, Ed25519PublicKey) or isinstance(public, Ed448PublicKey):
        return SuiteId.EDDSA_CSHAKE128
    raise TypeError('Public key algorithm not supported')


def generate_key_pair(
    oga_id: SuiteId,
    rsa_key_size: OrchidDsaRsaKeySizes = 2048,
    ecdsa_curve: OrchidEcdsaCurves = 'P-256',
    eddsa_curve: OrchidEddsaCurves = 'Ed25519'
) -> tuple[OrchidPublicKeyAlgorithms, OrchidPrivateKeyAlgorithms]:
    match oga_id:
        case SuiteId.RSA_DSA_SHA256:
            _rsa = rsa.generate_private_key(65537, rsa_key_size)
            _public, _private = _rsa.public_key(), _rsa
        case SuiteId.ECDSA_SHA384:
            if ecdsa_curve == 'P-256': _ecdsa = ec.generate_private_key(ec.SECP256R1())
            else: _ecdsa = ec.generate_private_key(ec.SECP384R1())
            _public, _private = _ecdsa.public_key(), _ecdsa
        case SuiteId.EDDSA_CSHAKE128:
            _eddsa = Ed25519PrivateKey.generate() if eddsa_curve == 25519 else Ed448PrivateKey.generate()
            _public, _private = _eddsa.public_key(), _eddsa
        case _:
            raise NotImplementedError(f"SuiteId={oga_id} not supported")
    return _public, _private


def load_pem_key(
    pem_data: bytes,
    password: bytes | None = None
) -> tuple[OrchidPublicKeyAlgorithms, OrchidPrivateKeyAlgorithms]:
    if password:
        _private = load_pem_private_key(pem_data, password)
        _public = _private.public_key()
    else:
        _public, _private = load_pem_public_key(pem_data, None), None
    _public: OrchidPublicKeyAlgorithms
    match suite_id_by_public_key_alg(_public):
        case SuiteId.RSA_DSA_SHA256:
            _public: RSAPublicKey
            _private: RSAPrivateKey
            return _public, _private
        case SuiteId.ECDSA_SHA384:
            _public: EllipticCurvePublicKey
            _private: EllipticCurvePrivateKey
            return _public, _private
        case SuiteId.EDDSA_CSHAKE128:
            _public: Ed448PublicKey | Ed25519PublicKey
            _private: Ed448PrivateKey | Ed25519PrivateKey
            return _public, _private
        case _:
            raise TypeError('key algorithm not supported')


def construct_host_identity(public: OrchidPublicKeyAlgorithms) -> bytes:
    match suite_id_by_public_key_alg(public):
        case SuiteId.RSA_DSA_SHA256:
            public: RSAPublicKey
            _nums = public.public_numbers()
            _e_size = (_nums.e.bit_length() + 7) // 8
            _e_len = _e_size.to_bytes(3 if _e_size > 255 else 1)
            _e = _nums.e.to_bytes(_e_size)
            _n = _nums.n.to_bytes((_nums.n.bit_length() + 7) // 8)
            return _e_len + _e + _n
        case SuiteId.ECDSA_SHA384:
            public: EllipticCurvePublicKey
            _curve = (1 if public.curve == ec.SECP256R1 else 2).to_bytes(2)
            return _curve + public.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
        case SuiteId.EDDSA_CSHAKE128:
            public: Ed25519PublicKey | Ed448PublicKey
            _curve = (1 if isinstance(public, Ed25519PublicKey) else 3).to_bytes(2)
            return _curve + public.public_bytes_raw()
        case _:
            raise TypeError('key algorithm not supported')


def construct_ip(
    public: OrchidPublicKeyAlgorithms,
    prefix: Prefix,
    info: bytes | None = None,
    ctx_id: ContextId = ContextId.RFC7401
) -> IPv6Address:
    _suite_id = suite_id_by_public_key_alg(public)
    _prefix_info_oga = _construct_prefix_info_oga(prefix, SuiteId.RSA_DSA_SHA256, info)
    _hih_length = 16 - len(_prefix_info_oga)
    match _suite_id:
        case SuiteId.RSA_DSA_SHA256:
            _hih = _extract_bits(
                SHA256.new(ctx_id.value + _prefix_info_oga + construct_host_identity(public)).digest(),
                _hih_length * 8
            )
        case SuiteId.ECDSA_SHA384:
            _hih = _extract_bits(
                SHA384.new(ctx_id.value + _prefix_info_oga + construct_host_identity(public)).digest(),
                _hih_length * 8
            )
        case SuiteId.EDDSA_CSHAKE128:
            _hih = cSHAKE128.new(
                _prefix_info_oga + construct_host_identity(public),
                custom=ctx_id.value
            ).read(_hih_length)
        case _:
            raise TypeError('key algorithm not supported')
    return IPv6Address(_prefix_info_oga + _hih)


def _construct_prefix_info_oga(prefix: Prefix, oga_id: SuiteId, info: bytes | None = None) -> bytes:
    # info & oga_id length is determined by the prefix in use
    match prefix:
        case Prefix.HIT:
            if oga_id > 15: raise ValueError("Non-valid SuiteId for HITs")  # ensures 4-bit oga_id
            # enum=32-bits w/tail 0, no need to shift just fill in lower 4-bits
            _prefix = int.from_bytes(prefix.value) | oga_id.value
            return _prefix.to_bytes(4)
        case Prefix.DET:
            if not info: raise ValueError('No info provided')
            # enum=32-bits w/tail 0, shift 24 and fill lower 28-bits with info
            _prefix = (int.from_bytes(prefix.value) << 24) | int.from_bytes(info)
            _prefix = _prefix << 8 | oga_id.value
            return _prefix.to_bytes(8)
        case _:
            raise ValueError('Prefix not supported')


def _extract_bits(data: bytes, bits: int) -> bytes:
    m = len(data) // 2  # find middle byte
    l = (bits // 8) // 2  # half number of bytes needed
    return data[m - l:m + l]
