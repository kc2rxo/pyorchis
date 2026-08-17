import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import unhexlify, hexlify
from ipaddress import IPv6Address
from typing import Literal, Any, get_args

import cbor2
from Crypto.Hash import cSHAKE128, SHA256, SHA384
from Crypto.PublicKey import DSA, RSA, ECC
from Crypto.Signature import eddsa

from src.orchis.constant import ContextId, Prefix, SuiteId


OrchisAlgorithm = Literal['DSA', 'RSA', 'ECDSA', 'EdDSA']
OrchisKey = DSA.DsaKey | RSA.RsaKey | ECC.EccKey
OrchisKeySize = Literal[2048, 3072]
OrchisKeyCurve = Literal['P-256', 'P-384', 'Ed25519', 'Ed448']
OrchisRsaAlgorithms = Literal['PS256', 'PS384', 'PS512']
OrchisFormats = Literal['PEM', 'DER', 'OpenSSH', 'raw', 'JWK', 'COSEKey']


def generate(
        alg: OrchisAlgorithm,
        dsa: OrchisKeySize = 2048,
        rsa: OrchisKeySize = 2048,
        curve: OrchisKeyCurve = 'Ed25519'
) -> OrchisKey:
    if alg == 'DSA':
        return DSA.generate(dsa)
    elif alg == 'RSA':
        return RSA.generate(rsa)
    elif alg == 'ECDSA' and (curve == 'P-256' or curve == 'P-384'):
        return ECC.generate(curve=curve)
    elif alg == 'EdDSA' and (curve == 'Ed25519' or curve == 'Ed448'):
        return ECC.generate(curve=curve)
    else:
        raise ValueError(f'{alg} {dsa}/{rsa}/{curve} not supported')


def dump_key(key: OrchisKey, fmt: OrchisFormats, password: str | bytes | None = None) -> bytes | str:
    if isinstance(key, DSA.DsaKey):
        if fmt not in ('PEM', 'DER', 'OpenSSH'):
            raise ValueError('DSA dump formats: PEM, DER, OpenSSH')
        if isinstance(password, bytes):
            password = password.decode('utf-8')
        return key.export_key(format=fmt, passphrase=password)
    elif isinstance(key, RSA.RsaKey):
        if fmt not in ('PEM', 'DER', 'OpenSSH'):
            raise ValueError('RSA dump formats: PEM, DER, OpenSSH')
        if isinstance(password, bytes):
            password = password.decode('utf-8')
        return key.export_key(format=fmt, passphrase=password)
    elif isinstance(key, ECC.EccKey):
        if key.curve not in ('NIST P-256', 'NIST P-384', 'Ed25519', 'Ed448'):
            raise ValueError('ECC dump curves: P-256, P-384, Ed25519, Ed448')
        if fmt not in ('PEM', 'OpenSSH') and fmt not in ('DER', 'raw'):
            raise ValueError('ECC dump formats: PEM, DER, OpenSSH, raw')
        if password: return key.export_key(format=fmt, passphrase=password)
        else: return key.export_key(format=fmt)
    else:
        raise ValueError('Key type not supported for dumping')


def load_key(data: bytes | str, password: str | bytes | None = None) -> OrchisKey:
    for key_type in get_args(OrchisAlgorithm):
        try:
            if key_type == 'DSA':
                if isinstance(password, bytes): password = password.decode('utf-8')
                return DSA.import_key(data, password)
            elif key_type == 'RSA':
                if isinstance(password, bytes): password = password.decode('utf-8')
                return RSA.import_key(data, password)
            elif key_type == 'ECC':
                if isinstance(password, bytes): password = password.decode('utf-8')
                return ECC.import_key(data, password)
            else:
                raise ValueError(f'failed to load {key_type}')
        except ValueError as e:
            print(e)
            continue
    raise ValueError('key failed to load')


def dump_jwk(key: OrchisKey, key_id: str, alg: OrchisRsaAlgorithms, private: bool = False, serialize: bool = False) -> str | dict[str, Any]:
    if isinstance(key, DSA.DsaKey): raise ValueError('DSA not supported for COSE Key')
    _params = {'kid': key_id}
    return json.dumps(_to_params(_params, key, alg)) if serialize else _params


def load_jwk(data: str) -> tuple[OrchisKey, str]:
    _jwk = json.loads(data)
    if not isinstance(_jwk, dict): raise TypeError('improper JWK format')
    return _from_params(_jwk) + (_jwk.get('kid', ''),)


def dump_cose_key(key: OrchisKey, key_id: bytes, alg: OrchisRsaAlgorithms, private: bool = False, serialize: bool = False) -> bytes | dict[int, Any]:
    if isinstance(key, DSA.DsaKey): raise ValueError('DSA not supported for COSE Key')
    _params: dict[int, Any] = {2: key_id}
    return cbor2.dumps(_to_params(_params, key, alg)) if serialize else _params


def load_cose_key(data: bytes) -> tuple[OrchisKey, bytes]:
    _key = cbor2.loads(data)
    if not isinstance(_key, dict): raise TypeError('improper COSE Key format')
    return _from_params(_key), _key.get(2, bytes())



def suite_id_from_public_key_alg(public: OrchisKey) -> SuiteId:
    """
    Selects a SuiteID from public key algorithm

    Args:
        public: public key instance

    Returns:
        SuiteId instance
    """
    if isinstance(public, DSA.DsaKey) or isinstance(public, RSA.RsaKey):
        return SuiteId.RSA_DSA_SHA256
    elif isinstance(public, ECC.EccKey) and public.curve in ('NIST P-256', 'NIST P-384'):
        return SuiteId.ECDSA_SHA384
    elif isinstance(public, ECC.EccKey) and public.curve in ('Ed25519', 'Ed448'):
        return SuiteId.EDDSA_CSHAKE128
    raise TypeError('Public key algorithm not supported')



def construct_host_identity(key: OrchisKey) -> bytes:
    """
    Host Identity field of HOST_ID parameter from RFC7401.

    Args:
        key: key instance to be used.

    Returns:
        bytes of the Host Identity field of HOST_ID parameter
    """
    public = key.public_key() if key.has_private() else key
    match suite_id_from_public_key_alg(public):
        case SuiteId.RSA_DSA_SHA256:
            public: RSA.RsaKey
            _e_size = (public.e.bit_length() + 7) // 8
            _e_len = _e_size.to_bytes(3 if _e_size > 255 else 1)
            _e = public.e.to_bytes(_e_size)
            _n = public.n.to_bytes((public.n.bit_length() + 7) // 8)
            return _e_len + _e + _n
        case SuiteId.ECDSA_SHA384:
            public: ECC.EccKey
            _curve = (1 if public.curve == 'P-256' else 2).to_bytes(2)
            return _curve + public.export_key(format='raw')
        case SuiteId.EDDSA_CSHAKE128:
            public: ECC.EccKey
            _curve = (1 if public.curve == 'Ed25519' else 3).to_bytes(2)
            return _curve + public.export_key(format='raw')
        case _:
            raise TypeError('key algorithm not supported')


def load_key_id(
        kid: str | bytes | None,
        public: OrchisKey,
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
        public: OrchisKey,
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


def _to_params(
        params: dict[int, Any] | dict[str, Any],
        key: OrchisKey,
        alg: OrchisRsaAlgorithms = 'PS256'
) -> dict[str, Any] | dict[int, Any]:
    if key is None: raise ValueError('no key specified')
    is_jwk = all(isinstance(k, str) for k, _ in params.items())
    if isinstance(key, RSA.RsaKey):
        _params = _rsa_to_params(key, params, is_jwk, alg)
    elif isinstance(key, ECC.EccKey):
        _params = _ecc_to_params(key, params, is_jwk)
    else:
        raise TypeError('key algorithm not supported')
    return _params


def _rsa_to_params(
        key: RSA.RsaKey,
        params: dict,
        is_jwk: bool,
        alg: OrchisRsaAlgorithms = 'PS256'
) -> dict[str, Any] | dict[int, Any]:
    params.update({'kty' if is_jwk else 1 : 'RSA' if is_jwk else 3})
    params.update({
        'n' if is_jwk else -1: _int_to_bytes(key.n, True) if is_jwk else _int_to_bytes(key.n),
        'e' if is_jwk else -2: _int_to_bytes(key.e, True) if is_jwk else _int_to_bytes(key.e),
    })
    if key.has_private():
        params.update({
            'd' if is_jwk else -3 : _int_to_bytes(key.d, True) if is_jwk else _int_to_bytes(key.d),
            'p' if is_jwk else -4 : _int_to_bytes(key.p, True) if is_jwk else _int_to_bytes(key.p),
            'q' if is_jwk else -5 : _int_to_bytes(key.q, True) if is_jwk else _int_to_bytes(key.q),
            'dp' if is_jwk else -6 : _int_to_bytes(key.invp, True) if is_jwk else _int_to_bytes(key.invp),
            'dq' if is_jwk else -7 : _int_to_bytes(key.invq, True) if is_jwk else _int_to_bytes(key.invq),
            'qi' if is_jwk else -8 : _int_to_bytes(key.u, True) if is_jwk else _int_to_bytes(key.u)
        })
    if is_jwk:
        params.update({'alg': alg})
    elif alg == 'PS256':
        params.update({3: -257})
    elif alg == 'PS384':
        params.update({3: -258})
    elif alg == 'PS512':
        params.update({3: -259})
    return params


def _ecc_to_params(
        key: ECC.EccKey,
        params: dict,
        is_jwk: bool
) -> dict[str, Any] | dict[int, Any]:
    if key.curve in ('P-256', 'P-384'):
        params.update({'kty' if is_jwk else 1 : 'EC' if is_jwk else 2})
        _crv = ('P-256' if is_jwk else 1) if key.curve == 'NIST P-256' else ('P-384' if is_jwk else 2)
        params.update({'crv' if is_jwk else -1: _crv})
        _size = key.pointQ.size_in_bits()
        _x = _int_to_bytes(key.pointQ.x, True, _size) if is_jwk else _int_to_bytes(key.pointQ.x)
        _y = _int_to_bytes(key.pointQ.y, True, _size) if is_jwk else _int_to_bytes(key.pointQ.y)
        if key.has_private():
            params.update({
                'x' if is_jwk else -2 : _x,
                'y' if is_jwk else -3 : _y,
                'd' if is_jwk else -4 : _int_to_bytes(key.d, True, _size) if is_jwk else _int_to_bytes(key.d),
            })
        else:
            params.update({
                'x' if is_jwk else -2 : _x,
                'y' if is_jwk else -3 : _y,
            })
    elif key.curve in ('Ed25519', 'Ed448'):
        params.update({'kty' if is_jwk else 1 : 'OKP' if is_jwk else 1})
        _crv = ('Ed25519' if is_jwk else 6) if key.curve == 'Ed25519' else ('Ed448' if is_jwk else 7)
        params.update({'crv' if is_jwk else -1 : _crv})
        _public = key.public_key().export_key(format='raw')
        if key.has_private():
            params.update({
                'x' if is_jwk else -2 : urlsafe_b64encode(_public).decode('utf-8') if is_jwk else _public,
                'd' if is_jwk else -3 : urlsafe_b64encode(key.seed).decode('utf-8') if is_jwk else key.seed,
            })
        else:
            params.update({
                'x' if is_jwk else -2 : urlsafe_b64encode(_public).decode('utf-8') if is_jwk else _public,
            })
    else:
        raise TypeError('ecc curve not supported')
    return params


def _from_params(params: dict[int, Any] | dict[str, Any]) -> OrchisKey:
    is_jwk = all(isinstance(k, str) for k, _ in params.items())
    params: dict[str | int, Any]
    if params['kty' if is_jwk else 1] == 'RSA' if is_jwk else 3: return _rsa_from_params(params, is_jwk)
    elif params['kty' if is_jwk else 1] == 'EC' if is_jwk else 2: return _ecc_from_params(params, is_jwk)
    elif params['kty' if is_jwk else 1] == 'OKP' if is_jwk else 1: return _ecc_from_params(params, is_jwk)
    else:
        raise TypeError('key algorithm not supported')


def _kid_from_params(params: dict, is_jwk: bool) -> bytes | str:
    return params.get('kid' if is_jwk else 2, '' if is_jwk else bytes())


def _rsa_from_params(params: dict, is_jwk: bool) -> OrchisKey:
    _n = int(hexlify(_base64url_decode(params['n' if is_jwk else -1])), 16)
    _e = int(hexlify(_base64url_decode(params['e' if is_jwk else -2])), 16)
    if  ('d' not in params) or (-3 not in params):
        key = RSA.construct((_n, _e))
    else:
        _d = int(hexlify(_base64url_decode(params['d' if is_jwk else -3])), 16)
        key = RSA.construct((_n, _e, _d))
    return key


def _ecc_from_params(params: dict, is_jwk: bool) -> OrchisKey:
    _crv = params['crv' if is_jwk else -1]
    _x = params['x' if is_jwk else -2]
    if _crv in (1, 2) or _crv in ('P-256', 'P-384'):
        _x = int(hexlify(_base64url_decode(_x)), 16) if is_jwk else int.from_bytes(_x)
        if _crv in (1, 2): _crv = 'P-256' if _crv == 1 else 'P-384'
        _y = params['y' if is_jwk else -3]
        _y = int(hexlify(_base64url_decode(_y)), 16) if is_jwk else int.from_bytes(_y)
        if ('d' not in params) or (-4 not in params):
            key = ECC.construct(curve=_crv, point_x=_x, point_y=_y)
        else:
            _d = params['d' if is_jwk else -4]
            _d = int(hexlify(_base64url_decode(_d)), 16) if is_jwk else int.from_bytes(_d)
            key = ECC.construct(curve=_crv, d=_d)
    elif _crv in (6, 7) or _crv in ('Ed25519', 'Ed448'):
        if ('d' not in params) or (-4 not in params):
            key = eddsa.import_public_key(_base64url_decode(_x))
        else:
            key = eddsa.import_private_key(_base64url_decode(params['d' if is_jwk else -4]))
    else:
        raise TypeError('ecc curve not supported')
    return key


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


def _base64url_decode(payload: str) -> bytes:
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))