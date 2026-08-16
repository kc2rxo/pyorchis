import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import unhexlify, hexlify
from copy import deepcopy
from ipaddress import IPv6Address
from typing import Literal, Any

import cbor2
from Crypto.Hash import cSHAKE128, SHA256, SHA384
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey, Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from src.orchis.constant import ContextId, Prefix, SuiteId


OrchisPublicKeyAlgorithms = Ed448PublicKey | Ed25519PublicKey | RSAPublicKey | EllipticCurvePublicKey
OrchisPrivateKeyAlgorithms = Ed448PrivateKey | Ed25519PrivateKey | RSAPrivateKey | EllipticCurvePrivateKey
OrchisRsaKeySizes = Literal[2048, 4096, 8192]
OrchisRsaAlgorithms = Literal['PS256', 'PS384', 'PS512']
OrchisEcdsaCurves = Literal['P-256', 'P-384']
OrchisEddsaCurves = Literal['Ed448', 'Ed25519']


def suite_id_from_public_key_alg(public: OrchisPublicKeyAlgorithms) -> SuiteId:
    """
    Selects a SuiteID from public key algorithm

    Args:
        public: public key instance

    Returns:
        SuiteId instance
    """
    if isinstance(public, RSAPublicKey):
        return SuiteId.RSA_DSA_SHA256
    elif isinstance(public, EllipticCurvePublicKey):
        return SuiteId.ECDSA_SHA384
    elif isinstance(public, Ed25519PublicKey) or isinstance(public, Ed448PublicKey):
        return SuiteId.EDDSA_CSHAKE128
    raise TypeError('Public key algorithm not supported')


def generate_key_pair(
        oga_id: SuiteId,
        rsa_key_size: OrchisRsaKeySizes = 2048,
        ecdsa_curve: OrchisEcdsaCurves = 'P-256',
        eddsa_curve: OrchisEddsaCurves = 'Ed25519'
) -> tuple[OrchisPublicKeyAlgorithms, OrchisPrivateKeyAlgorithms]:
    """
    Generates new instances of public and private keys for a given Orchid Generation Algorithm ID (OGA ID).

    Args:
        oga_id: selection of SuiteId from HIT or HHIT
        rsa_key_size: preferred RSA key size (2048, 4069, 8192), default=2048
        ecdsa_curve: preferred ECDSA curve (NIST P-256, NIST P-384), default=P-256
        eddsa_curve: preferred EdDSA curve (Ed25519, Ed448), default=Ed25519

    Returns:
        Instances of public and private keys from cryptography
    """
    match oga_id:
        case SuiteId.RSA_DSA_SHA256:
            _rsa = rsa.generate_private_key(65537, rsa_key_size)
            _public, _private = _rsa.public_key(), _rsa
        case SuiteId.ECDSA_SHA384:
            if ecdsa_curve == 'P-256':
                _ecdsa = ec.generate_private_key(ec.SECP256R1())
            else:
                _ecdsa = ec.generate_private_key(ec.SECP384R1())
            _public, _private = _ecdsa.public_key(), _ecdsa
        case SuiteId.EDDSA_CSHAKE128:
            _eddsa = Ed25519PrivateKey.generate() if eddsa_curve == 25519 else Ed448PrivateKey.generate()
            _public, _private = _eddsa.public_key(), _eddsa
        case _:
            raise NotImplementedError(f"SuiteId={oga_id} not supported")
    return _public, _private


def dump_pem_key(
        key: OrchisPrivateKeyAlgorithms | OrchisPublicKeyAlgorithms | None,
        password: bytes | None = None,
) -> bytes:
    """
    All PEMs are PKCS8 for PrivateFormat. RSA uses PublicFormat.PKCS1, ECDSA uses PublicFormat.SubjectPublicKeyInfo
    and EdDSA uses PublicFormat.Raw.

    Encryption is BestAvailableEncryption from cryptography package with provided password.

    Args:
        key:
        password:

    Returns:
        PEM data in bytes
    """
    if key is None: raise ValueError('no key specified')
    if isinstance(key, OrchisPrivateKeyAlgorithms):
        key: OrchisPrivateKeyAlgorithms
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    else:
        key: OrchisPublicKeyAlgorithms
        if isinstance(key, RSAPublicKey):
            fmt = serialization.PublicFormat.PKCS1
        elif isinstance(key, Ed25519PublicKey):
            fmt = serialization.PublicFormat.Raw
        else:
            fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        return key.public_bytes(serialization.Encoding.PEM, fmt)


def load_pem_key(
        pem_data: bytes,
        password: bytes | None = None
) -> tuple[OrchisPublicKeyAlgorithms, OrchisPrivateKeyAlgorithms]:
    """
    Loads PEM data to instances of public and private keys.

    Args:
        pem_data: bytes of PEM data
        password: optional encryption password, default=None

    Returns:
        Instances of public and private keys from cryptography
    """
    if password:
        _private = load_pem_private_key(pem_data, password)
        _public = _private.public_key()
    else:
        _public, _private = load_pem_public_key(pem_data, None), None
    _public: OrchisPublicKeyAlgorithms
    match suite_id_from_public_key_alg(_public):
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


def key_to_cose_key(
        key: OrchisPrivateKeyAlgorithms | OrchisPublicKeyAlgorithms | None,
        key_id: bytes,
        rsa_alg: OrchisRsaAlgorithms = 'PS256',
        serialize: bool = True,
) -> bytes | dict[int, Any]:
    """
    Converts a cryptography key to COSE Key format.

    Args:
        key: OrchisPrivateKeyAlgorithms
        rsa_alg: OrchisRsaAlgorithms, default='PS256'
        key_id: bytes
        serialize: bool, default=True

    Returns:
        COSEKeyInterface of pyca key
    """
    _params: dict[int, Any] = {2: key_id}
    return cbor2.dumps(_to_params(_params, key, rsa_alg)) if serialize else _params


def cose_key_to_key(cose_key: bytes) -> tuple[OrchisPublicKeyAlgorithms, OrchisPrivateKeyAlgorithms | None, bytes]:
    """
    Converts a COSE Key into a cryptography key.

    Args:
        cose_key: decoded COSE Key

    Returns:
        Instances of public and private keys from cryptography and Key ID
    """
    _key = cbor2.loads(cose_key)
    if not isinstance(_key, dict): raise TypeError('improper COSE Key format')
    return _from_params(_key) + (_key.get(2, bytes()),)


def key_to_jwk(
        key: OrchisPrivateKeyAlgorithms | OrchisPublicKeyAlgorithms | None,
        key_id: str,
        rsa_alg: OrchisRsaAlgorithms = 'PS256',
        serialize: bool = True
) -> str | dict[str, Any]:
    _params = {'kid': key_id}
    return json.dumps(_to_params(_params, key, rsa_alg)) if serialize else _params


def jwk_to_key(jwk: str) -> tuple[OrchisPublicKeyAlgorithms, OrchisPrivateKeyAlgorithms | None, str]:
    pass  # todo: removes interdependency on Orchid.import_pem() that is currently in use
    _jwk = json.loads(jwk)
    if not isinstance(_jwk, dict): raise TypeError('improper JWK format')
    return _from_params(_jwk) + (_jwk.get('kid', ''),)


def construct_host_identity(public: OrchisPublicKeyAlgorithms) -> bytes:
    """
    Host Identity field of HOST_ID parameter from RFC7401.

    Args:
        public: public key instance to be used.

    Returns:
        bytes of the Host Identity field of HOST_ID parameter
    """
    match suite_id_from_public_key_alg(public):
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


def load_key_id(
        kid: str | bytes | None,
        public: OrchisPublicKeyAlgorithms,
        prefix: Prefix = Prefix.HIT,
        info: bytes | None = None
) -> IPv6Address:
    """
    Attempts to load a COSE/JOSE Key ID into an IPv6 address. Otherwise uses public key
    and parameters to create new Key ID based on ORCHID.

    Args:
        kid: existing Key ID from COSE/JOSE
        public: instance of OrchisPublicKeyAlgorithms to use to create new Key ID
        prefix: optional Prefix to use if JWK does not have an ORCHID Key ID, default=Prefix.HIT
        info: optional additional info to use if JWK does not have an ORCHID Key ID, default=None

    Returns:
        An IPv6 Address instance with ORCHID
    """
    try:
        return IPv6Address(kid)
    except ValueError:
        return construct_ip(
            public,
            prefix,
            info,
            ContextId.RFC7401 if prefix is Prefix.HIT else ContextId.RFC9374
        )


def construct_ip(
        public: OrchisPublicKeyAlgorithms,
        prefix: Prefix,
        info: bytes | None = None,
        ctx_id: ContextId = ContextId.RFC7401
) -> IPv6Address:
    """
    Constructs an ORCHID per RFC7401 and RFC9374.

    Args:
        public: public key instance to be used
        prefix: Prefix instance to be used
        info: optional bytes of additional information (per RFC9374), default=None
        ctx_id: ContextId instance to be used, default=ContextId.RFC7401

    Returns:
        An instance of IPv6Address containing constructed ORCHID
    """
    _suite_id = suite_id_from_public_key_alg(public)
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


def _int_to_bytes(val: int, base_64: bool = False, bit_size: int | None = None) -> bytes | str:
    _bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    if base_64:
        extend = 0
        if bit_size is not None:
            extend = ((bit_size + 7) // 8) * 2
        hex_val = hex(val).rstrip("L").lstrip("0x")
        hex_len = len(hex_val)
        if extend > hex_len:
            extend -= hex_len
        else:
            extend = hex_len % 2
        encode = urlsafe_b64encode(unhexlify(extend * '0' + hex_val))
        return encode.decode('utf-8').rstrip('=')
    return _bytes


def _to_params(
        params: dict[int, Any] | dict[str, Any],
        key: OrchisPublicKeyAlgorithms | OrchisPrivateKeyAlgorithms | None,
        rsa_alg: OrchisRsaAlgorithms = 'PS256'
) -> dict[str, Any] | dict[int, Any]:
    if key is None: raise ValueError('no key specified')
    is_jwk = all(isinstance(k, str) for k, _ in params.items())
    if isinstance(key, (RSAPrivateKey, RSAPublicKey)):
        _params = _rsa_to_params(key, params, is_jwk, rsa_alg)
    elif isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
        _params = _ecdsa_to_params(key, params, is_jwk)
    elif isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey)):
        _params = _eddsa_to_params(key, params, is_jwk)
    else:
        raise TypeError('key algorithm not supported')
    return _params


def _rsa_to_params(
        key: RSAPublicKey | RSAPrivateKey,
        params: dict[str, Any] | dict[int, Any],
        is_jwk: bool,
        rsa_alg: OrchisRsaAlgorithms = 'PS256'
) -> dict[str, Any] | dict[int, Any]:
    _params = deepcopy(params)
    if is_jwk:
        _params: dict[str, Any]
        _params.update({'kty': 'RSA'})
    else:
        _params: dict[int, Any]
        _params.update({1: 3})
    if isinstance(key, RSAPrivateKey):
        _pn = key.private_numbers()
        if is_jwk:
            _params.update({
                'n': _int_to_bytes(_pn.public_numbers.n, True),
                'e': _int_to_bytes(_pn.public_numbers.e, True),
                'd': _int_to_bytes(_pn.d, True),
                'p': _int_to_bytes(_pn.p, True),
                'q': _int_to_bytes(_pn.q, True),
                'dp': _int_to_bytes(_pn.dmp1, True),
                'dq': _int_to_bytes(_pn.dmq1, True),
                'qi': _int_to_bytes(_pn.iqmp, True)
            })
        else:
            _params: dict[int, Any]
            _params.update({
                -1: _int_to_bytes(_pn.public_numbers.n),
                -2: _int_to_bytes(_pn.public_numbers.e),
                -3: _int_to_bytes(_pn.d),
                -4: _int_to_bytes(_pn.p),
                -5: _int_to_bytes(_pn.q),
                -6: _int_to_bytes(_pn.dmp1),
                -7: _int_to_bytes(_pn.dmq1),
                -8: _int_to_bytes(_pn.iqmp)
            })
    else:  # public key
        if is_jwk:
            _params.update({
                'n': _int_to_bytes(key.public_numbers().n, True),
                'e': _int_to_bytes(key.public_numbers().e, True)
            })
        else:
            _params: dict[int, Any]
            _params.update({
                -1: _int_to_bytes(key.public_numbers().n),
                -2: _int_to_bytes(key.public_numbers().e),
            })
    if is_jwk:
        _params.update({'alg': rsa_alg})
    elif rsa_alg == 'PS256':
        _params: dict[int, Any]
        _params.update({3: -257})
    elif rsa_alg == 'PS384':
        _params: dict[int, Any]
        _params.update({3: -258})
    elif rsa_alg == 'PS512':
        _params: dict[int, Any]
        _params.update({3: -259})
    return _params


def _ecdsa_to_params(
        key: EllipticCurvePublicKey | EllipticCurvePrivateKey,
        _params: dict[str, Any] | dict[int, Any],
        is_jwk: bool
) -> dict[str, Any] | dict[int, Any]:
    if is_jwk:
        _params.update({'kty': 'EC'})
    else:
        _params: dict[int, Any]
        _params.update({1: 2})
    if isinstance(key.curve, ec.SECP256R1):
        if is_jwk:
            _params.update({'crv': 'P-256'})
        else:
            _params: dict[int, Any]
            _params.update({-1: 1})
    elif isinstance(key.curve, ec.SECP384R1):
        if is_jwk:
            _params.update({'crv': 'P-384'})
        else:
            _params: dict[int, Any]
            _params.update({-1: 2})
    if isinstance(key, EllipticCurvePrivateKey):
        _pn = key.private_numbers()
        if is_jwk:
            _params.update({
                'x': _int_to_bytes(_pn.public_numbers.x, True, _pn.public_numbers.curve.key_size),
                'y': _int_to_bytes(_pn.public_numbers.y, True, _pn.public_numbers.curve.key_size),
                'd': _int_to_bytes(_pn.private_value, True, _pn.public_numbers.curve.key_size),
            })
        else:
            _params: dict[int, Any]
            _params.update({
                -2: _int_to_bytes(_pn.public_numbers.x),
                -3: _int_to_bytes(_pn.public_numbers.y),
                -4: _int_to_bytes(_pn.private_value)
            })
    else:
        if is_jwk:
            _params.update({
                'x': _int_to_bytes(key.public_numbers().x, True, key.public_numbers().curve.key_size),
                'y': _int_to_bytes(key.public_numbers().y, True, key.public_numbers().curve.key_size),
            })
        else:
            _params: dict[int, Any]
            _params.update({
                -2: _int_to_bytes(key.public_numbers().x),
                -3: _int_to_bytes(key.public_numbers().y),
            })
    return _params


def _eddsa_to_params(
        key: Ed25519PublicKey | Ed448PublicKey| Ed25519PrivateKey | Ed448PrivateKey,
        _params: dict[str, Any] | dict[int, Any],
        is_jwk: bool
) -> dict[str, Any] | dict[int, Any]:
    if is_jwk:
        _params.update({
            'kty': 'OKP',
            'crv': 'Ed25519' if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)) else 'Ed448'
        })
    else:
        _params: dict[int, Any]
        _params.update({
            1: 1,
            -1: 6 if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)) else 7
        })
    if isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
        if is_jwk:
            _params.update({'x': urlsafe_b64encode(key.public_bytes_raw()).decode('utf-8')})
        else:
            _params: dict[int, Any]
            _params.update({-2: key.public_bytes_raw()})
    else:
        if is_jwk:
            _params.update({
                'x': urlsafe_b64encode(key.public_key().public_bytes_raw()).decode('utf-8'),
                'd': urlsafe_b64encode(key.private_bytes_raw()).decode('utf-8')
            })
        else:
            _params: dict[int, Any]
            _params.update({
                -2: key.public_key().public_bytes_raw(),
                -3: key.private_bytes_raw()
            })
    return _params


def _from_params(params: dict[int, Any] | dict[str, Any]) -> tuple[OrchisPublicKeyAlgorithms, OrchisPrivateKeyAlgorithms | None]:
    if all(isinstance(k, int) for k, _ in params.items()):
        if params[1] == 3: return _rsa_from_params(params)
        elif params[1] == 2: return _ecdsa_from_params(params)
        elif params[1] == 1: return _eddsa_from_params(params)
        else:
            raise TypeError('key algorithm not supported')
    else:
        params: dict[str, Any]
        if params['kty'] == 'RSA': return _rsa_from_params(params)
        elif params['kty'] == 'EC': return _ecdsa_from_params(params)
        elif params['kty'] == 'OKP': return _eddsa_from_params(params)
        else:
            raise TypeError('key algorithm not supported')


def _kid_from_params(params: dict[int, Any] | dict[str, Any]) -> bytes | str:
    if all(isinstance(k, int) for k, _ in params.items()):
        params: dict[int, Any]
        return params.get(2, bytes())
    else:
        params: dict[str, Any]
        return params.get('kid', '')


def _rsa_from_params(params: dict[int, Any] | dict[str, Any]) -> tuple[RSAPublicKey, RSAPrivateKey | None]:
    if all(isinstance(k, int) for k, _ in params.items()):
        public_numbers = rsa.RSAPublicNumbers(int.from_bytes(params[-2]), int.from_bytes(params[-1]))
        if -3 not in params or -4 not in params or -5 not in params: return public_numbers.public_key(), None
        private_numbers = rsa.RSAPrivateNumbers(
            p=int.from_bytes(params[-4]),
            q=int.from_bytes(params[-5]),
            d=int.from_bytes(params[-3]),
            dmp1=int.from_bytes(params[-3]) % (int.from_bytes(params[-4]) - 1),
            dmq1=int.from_bytes(params[-3]) % (int.from_bytes(params[-5]) - 1),
            iqmp=pow(int.from_bytes(params[-5]), -1, int.from_bytes(params[-4])),
            public_numbers=public_numbers
        )
        return public_numbers.public_key(), private_numbers.private_key()
    else:
        params: dict[str, Any]
        public_numbers = rsa.RSAPublicNumbers(
            int(hexlify(_base64url_decode(params['e'])), 16),
            int(hexlify(_base64url_decode(params['n'])), 16)
        )
        if 'd' not in params or 'p' not in params or 'q' not in params: return public_numbers.public_key(), None
        private_numbers = rsa.RSAPrivateNumbers(
            p=int(hexlify(_base64url_decode(params['p'])), 16),
            q=int(hexlify(_base64url_decode(params['q'])), 16),
            d=int(hexlify(_base64url_decode(params['d'])), 16),
            dmp1=int(hexlify(_base64url_decode(params['d'])), 16) % (int(hexlify(_base64url_decode(params['p'])), 16) - 1),
            dmq1=int(hexlify(_base64url_decode(params['d'])), 16) % (int(hexlify(_base64url_decode(params['q'])), 16) - 1),
            iqmp=pow(int(hexlify(_base64url_decode(params['q'])), 16), -1,  int(hexlify(_base64url_decode(params['p'])), 16)),
            public_numbers=public_numbers
        )
        return public_numbers.public_key(), private_numbers.private_key()


def _ecdsa_from_params(params: dict[int, Any] | dict[str, Any]) -> tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey | None]:
    if all(isinstance(k, int) for k, _ in params.items()):
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(params[-2]),
            y=int.from_bytes(params[-3]),
            curve=ec.SECP256R1() if params[-1] == 1 else ec.SECP384R1(),
        )
        if -4 not in params: return public_numbers.public_key(), None
        private_numbers = ec.EllipticCurvePrivateNumbers(int.from_bytes(params[-4]), public_numbers)
        return public_numbers.public_key(), private_numbers.private_key()
    else:
        params: dict[str, Any]
        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int(hexlify(_base64url_decode(params['x'])), 16),
            y=int(hexlify(_base64url_decode(params['y'])), 16),
            curve=ec.SECP256R1() if params['crv'] == 'P-256' else ec.SECP384R1(),
        )
        if 'd' not in params: return public_numbers.public_key(), None
        private_numbers = ec.EllipticCurvePrivateNumbers(int(hexlify(_base64url_decode(params['d'])), 16), public_numbers)
        return public_numbers.public_key(), private_numbers.private_key()


def _eddsa_from_params(params: dict[int, Any] | dict[str, Any]) -> tuple[Ed25519PublicKey | Ed448PublicKey, Ed25519PrivateKey | Ed448PrivateKey | None]:
    if all(isinstance(k, int) for k, _ in params.items()):
        if params[-1] == 6:
            _pub = Ed25519PublicKey.from_public_bytes(params[-2])
            if -3 not in params: return _pub, None
            return _pub, Ed25519PrivateKey.from_private_bytes(params[-3])
        else:
            _pub = Ed448PublicKey.from_public_bytes(params[-2])
            if -3 not in params: return _pub, None
            return _pub, Ed448PrivateKey.from_private_bytes(params[-3])
    else:
        params: dict[str, Any]
        if params['crv'] == 'Ed25519':
            _pub = Ed25519PublicKey.from_public_bytes(_base64url_decode(params['x']))
            if 'd' not in params: return _pub, None
            return _pub, Ed25519PrivateKey.from_private_bytes(_base64url_decode(params['d']))
        else:
            _pub = Ed448PublicKey.from_public_bytes(_base64url_decode(params['x']))
            if 'd' not in params: return _pub, None
            return _pub, Ed448PrivateKey.from_private_bytes(_base64url_decode(params['d']))


def _base64url_decode(payload: str) -> bytes:
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))