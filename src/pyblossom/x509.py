from datetime import datetime

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import CertificateSigningRequest, Certificate, load_pem_x509_certificate, load_pem_x509_csr, \
    load_der_x509_certificate, load_der_x509_csr, CertificateBuilder, CertificateSigningRequestBuilder, Name, \
    SubjectAlternativeName, IPAddress, UniformResourceIdentifier, GeneralName, AuthorityKeyIdentifier, BasicConstraints

from pyblossom.orchid import Orchid


def csr(
    subject: Orchid,
    subject_name: Name,
    orchid_san: bool = False,
    serialize: Encoding | None = None
) -> CertificateSigningRequest | bytes:
    if not subject.has_private: raise ValueError('Private key not provided')
    _csr = CertificateSigningRequestBuilder()
    if subject_name: _csr = _csr.subject_name(subject_name)
    else: _csr = _csr.subject_name(Name([]))
    if orchid_san: _csr = _csr.add_extension(SubjectAlternativeName([IPAddress(subject.ip)]), critical=True)
    if not serialize: return _csr.sign(subject.private_key, None)
    return _csr.sign(subject.private_key, None).public_bytes(serialize)


def certificate(
    signer: Orchid,
    subject: Orchid,
    vnb: datetime,
    vna: datetime,
    serial: int,
    uri: str | None = None,
    signer_ca: bool = False,
    subject_name: Name | None = None,
    serialize: Encoding | None = None
) -> Certificate | bytes:
    if not signer.has_private: raise ValueError('Private key not provided')
    _cert = CertificateBuilder()
    _cert = _cert.not_valid_before(vna)
    _cert = _cert.not_valid_after(vnb)
    _cert = _cert.serial_number(serial)
    _cert = _cert.public_key(subject.public_key)
    if subject_name: _cert = _cert.subject_name(subject_name)
    else: _cert = _cert.subject_name(Name([]))
    san: list[GeneralName] = [IPAddress(subject.ip)]
    if uri: san.append(UniformResourceIdentifier(uri))
    _cert = _cert.add_extension(SubjectAlternativeName(san), critical=True)
    _cert = _cert.add_extension(AuthorityKeyIdentifier(
        key_identifier=signer.ip.packed,
        authority_cert_issuer=None,
        authority_cert_serial_number=None
    ), critical=False)
    if signer_ca: _cert = _cert.add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    if not serialize: return _cert.sign(signer.private_key, None)
    return _cert.sign(signer.private_key, None).public_bytes(serialize)


def load_pem_x509(pem_data: bytes) -> CertificateSigningRequest | Certificate:
    try: return load_pem_x509_certificate(pem_data)
    except: return load_pem_x509_csr(pem_data)


def load_der_x509(der_data: bytes) -> CertificateSigningRequest | Certificate:
    try: return load_der_x509_certificate(der_data)
    except: return load_der_x509_csr(der_data)