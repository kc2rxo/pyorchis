from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, load_der_private_key, load_der_public_key
    from cryptography.x509 import (
        CertificateSigningRequest,
        Certificate,
        load_pem_x509_certificate,
        load_pem_x509_csr,
        load_der_x509_certificate,
        load_der_x509_csr,
        CertificateBuilder,
        CertificateSigningRequestBuilder,
        Name,
        SubjectAlternativeName,
        IPAddress,
        UniformResourceIdentifier,
        GeneralName,
        AuthorityKeyIdentifier,
        BasicConstraints
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


from orchis.crypto import OrchisFormat
from orchis.orchid import Orchid


SignerKeys = Ed25519PrivateKey | Ed448PrivateKey | RSAPrivateKey | DSAPrivateKey | EllipticCurvePrivateKey


def csr(
        subject: Orchid,
        subject_name: Name,
        orchid_san: bool = False,
        fmt: OrchisFormat | None = None
) -> CertificateSigningRequest | bytes:
    """
    Creates a new X.509 CertificateSigningRequest using an ORCHID object.

    Args:
        subject: Orchid instance for subject, used to sign CSR
        subject_name: cryptography.x509.Name instance
        orchid_san: flag to include ORCHID as SubjectAlternativeName IP6, defaults=False
        fmt: instance of OrchisFormat, default=None

    Returns:
        Instance of cryptography.x509.CertificateSigningRequest or bytes
    """
    if not HAS_CRYPTO:
        raise ImportError('cryptography is not installed, install with pyorchis[x509]')
    if not subject.has_private: raise ValueError('Private key not provided')
    _subject = load_der_private_key(subject.dump(True, fmt='DER'), None)
    _csr = CertificateSigningRequestBuilder()
    _csr = _csr.subject_name(subject_name)
    if orchid_san: _csr = _csr.add_extension(SubjectAlternativeName([IPAddress(subject.ip)]), critical=True)
    if not fmt: return _csr.sign(_subject, None)
    return _sign_and_encode(_csr, _subject, fmt)


def certificate(
        issuer: Orchid,
        subject: Orchid,
        vnb: datetime,
        vna: datetime,
        serial: int,
        issuer_name: Name,
        subject_name: Name | None = None,
        uri: str | None = None,
        issuer_ca: bool = False,
        fmt: OrchisFormat | None = None
) -> Certificate | bytes:
    """
    Creates a new X.509 Certificate using ORCHID objects.

    Resulting certificate will use ORCHIDs for both Subject and Issuer that will be
    included in a Subject Alternative Name IP6 and an Authority Key Identifier extension.

    Args:
        issuer: Orchid instance for Issuer, used to sign Certificate
        subject: Orchid instance for Subject
        vnb: datetime of Valid Not Before
        vna: datetime of Valid Not After
        serial: int for Serial Number
        issuer_name: cryptography.x509.Name instance
        subject_name: x509.Name instance for subject name field, default=None
        uri: str for Subject Alternative Name URI, default=None
        issuer_ca: flag for Issuer being Certificate Authority, default=False
        fmt: instance of OrchisFormat, default=None

    Returns:
        Instance of cryptography.x509.Certificate or bytes
    """
    if not HAS_CRYPTO:
        raise ImportError('cryptography is not installed, install with pyorchis[x509]')
    if not issuer.has_private: raise ValueError('Private key not provided')
    _issuer = load_der_private_key(issuer.dump(True, fmt='DER'), None)
    _subject = load_der_public_key(subject.dump(fmt='DER'), None)
    _cert = CertificateBuilder()
    _cert = _cert.not_valid_before(vna)
    _cert = _cert.not_valid_after(vnb)
    _cert = _cert.serial_number(serial)
    _cert = _cert.public_key(_subject)
    if subject_name:
        _cert = _cert.subject_name(subject_name)
    else:
        _cert = _cert.subject_name(Name([]))
    san: list[GeneralName] = [IPAddress(subject.ip)]
    if uri: san.append(UniformResourceIdentifier(uri))
    _cert = _cert.add_extension(SubjectAlternativeName(san), critical=True)
    _cert = _cert.add_extension(AuthorityKeyIdentifier(
        key_identifier=issuer.ip.packed,
        authority_cert_issuer=None,
        authority_cert_serial_number=None
    ), critical=False)
    _cert = _cert.issuer_name(issuer_name)
    if issuer_ca: _cert = _cert.add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    if not fmt: return _cert.sign(_issuer, None)
    return _sign_and_encode(_cert, _issuer, fmt)


def load_pem_x509(pem_data: bytes) -> CertificateSigningRequest | Certificate:
    if not HAS_CRYPTO:
        raise ImportError('cryptography is not installed, install with pyorchis[x509]')
    try:
        return load_pem_x509_certificate(pem_data)
    except ValueError:
        return load_pem_x509_csr(pem_data)


def load_der_x509(der_data: bytes) -> CertificateSigningRequest | Certificate:
    if not HAS_CRYPTO:
        raise ImportError('cryptography is not installed, install with pyorchis[x509]')
    try:
        return load_der_x509_certificate(der_data)
    except ValueError:
        return load_der_x509_csr(der_data)


def _sign_and_encode(
        obj: CertificateSigningRequestBuilder | CertificateBuilder,
        signer: SignerKeys,
        fmt: OrchisFormat
) -> bytes:
    if fmt == 'PEM':
        return obj.sign(signer, None).public_bytes(Encoding.PEM)
    elif fmt == 'DER':
        return obj.sign(signer, None).public_bytes(Encoding.DER)
    else:
        raise ValueError('invalid serialization format: PEM, DER')