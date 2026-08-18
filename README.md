# ORCHIDs for Internet Applications & Protocols

Overlay Routable Cryptographic Hash IDentifiers (ORCHIDs) are valid non-routable addresses that are found under 
specific IANA assigned prefixes out of the IPv6 Special Purpose Address Space. They encode cryptographic
agility and optional additional information (such as hierarchy) while acting as a handle to the public portion 
of an asymmetric keypair.

An ORCHID is formed with the following general procedure:

1. Select an application specific Suite ID (selecting a key algorithm family and hash algorithm)
2. Generate an asymmetric key pair using the specified Suite ID algorithm family
3. Construct hash input string per application specification with public key
4. With the specified hash algorithm of Suite ID and application Context ID hash previous steps output
5. Assemble ORCHID using application provided prefix, Suite ID and resulting hash

The main protocols using ORCHIDs, with dedicated IPv6 prefixes, are the Host Identity Protocol (HIP, RFC7401) with 
the Host Identity Tag (HIT) generated through ORCHID and Drone Remote ID Protocol (DRIP, RFC9374) with the 
DRIP Entity Tag (DET) as its ORCHID. More on ORCHIDs in general can be found in RFC7343 and its predecessor RFC4843.

This project is designed as a reference implementation for ORCHIDs and provides a simple interface to generate and 
import them in Internet based applications or protocols. It is not intended to be a complete solution but rather a 
general toolbox for using of ORCHIDs.

> The project (pyorchis) is named after the plant family and genus that [orchids](https://en.wikipedia.org/wiki/Orchid) 
> are from.

## Cryptography Matrix

This project relies on `pycryptodome` to provide its cryptographic capabilities in support of ORCHID generation and
utility functions for HIP and DRIP.
 
| [H]HIT Suite ID | HI Algorithm | Key Algorithm | Curve      | Hash Algorithm | Supported          | Reference |
|-----------------|--------------|---------------|------------|----------------|--------------------|-----------|
| 1               | 3            | DSA           | -          | SHA-256        | :white_check_mark: | RFC7401   |
| 1               | 5            | RSA           | -          | SHA-256        | :white_check_mark: | RFC7401   |
| 2               | 7            | ECDSA         | NIST P-256 | SHA-384        | :white_check_mark: | RFC7401   |
| 2               | 7            | ECDSA         | NIST P-384 | SHA-384        | :white_check_mark: | RFC7401   |
| 3               | 9            | ECDSA_LOW     | SECP160R1  | SHA-1          | :x:                | RFC7401   |
| 5               | 13           | EdDSA         | Ed25519    | cSHAKE128      | :white_check_mark: | RFC9374   |
| 5               | 13           | EdDSA         | Ed25519ph  | cSHAKE128      | :x:                | RFC9374   |
| 5               | 13           | EdDSA         | Ed448      | cSHAKE128      | :white_check_mark: | RFC9374   |
| 5               | 13           | EdDSA         | Ed448ph    | cSHAKE128      | :x:                | RFC9374   |

Both RFC7401 prefix of `2001:20::/28` and RFC9374 prefix of `2001:30::/28` are supported.

## Import/Export Matrix

| Key Algorithm | Curve      | PEM/DER/OpenSSH    | Raw                | JSON Web Key       | COSE Key           |
|---------------|------------|--------------------|--------------------|--------------------|--------------------|
| DSA           | -          | :white_check_mark: | :x:                | :x:                | :x:                |
| RSA           | -          | :white_check_mark: | :x:                | :white_check_mark: | :white_check_mark: |
| ECDSA         | NIST P-256 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ECDSA         | NIST P-384 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| EdDSA         | Ed25519    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ECDSA         | Ed448      | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |

JWKs and COSE Keys are imported using their native encoded typing (`str`/`bytes`) and can be exported either
encoded or in `dict[int, Any]` for COSE Key and `dict[str, Any]` for JWK.

When exported as COSE Key/JWK, a Key ID is set using the ORCHID of the key. When imported with a Key ID an attempt is
made to convert it to an ORCHID or use the imported key to generate the ORCHID and set the `Orchid.ip`
attribute. A raw key import generates the ORCHID directly from incoming key material.

## HIP Support Capabilities

`Orchid.host_identity()` provides the "Host Identity" field for the HOST_ID parameter as defined in [Section 5.9.2 of
RFC7401](https://datatracker.ietf.org/doc/html/rfc7401#section-5.2.9).

## DRIP Support Capabilities

`Orchid.arpa()` returns the reverse lookup (i.e. nibble-reversed) IPv6 Fully Qualified Domain Name (FQDN) that is 
used by DRIP to enable lookups via [RFC9886](https://datatracker.ietf.org/doc/html/rfc9886).

---

`x509` is a module (installed with `pyorchis[x509]`) for X.509 CertificateSigningRequests & Certificates to be 
generated, dumped and loaded that follows the principals of 
[DRIP Key Infrastructure (DKI)](https://datatracker.ietf.org/doc/draft-ietf-drip-dki/).

It enforces the use of `Subject Alternative Name: IP6` for holding the Subject ORCHID and the extensions of
`Authority Key Identifier` for the Issuer ORCHID. These certificates are the "Canonical Registration Certificate" 
that are issued by levels of the hierarchy in DRIP and stored in the HHIT RRType of DNS.

---