# pyblossom: General-Use ORCHID Library for Modern Applications & Protocols

Overlay Routable Cryptographic Hash IDentifiers (ORCHIDs) are valid non-routable addresses that are found under 
specific IANA assigned prefixes out of the IPv6 Special Purpose Address Space. They encode directly cryptographic
agility and optional additional information (such as hierarchy) while acting as a handle to the public portion 
of an asymmetric keypair.

An ORCHID is formed with the following general procedure:

1. Select an application specific Suite ID (selecting a key algorithm family and hash algorithm)
2. Generate an asymmetric key pair using the specified Suite ID algorithm family
3. Construct hash input string per application specification with public key
4. With the specified hash algorithm of Suite ID and application Context ID hash previous steps output
5. Assemble ORCHID using application provided prefix, Suite ID and resulting hash

The main protocols using ORCHIDs, with dedicated IPv6 prefixes, are the Host Identity Protocol 
(HIP, RFC7401, `2001:20::/28`) with the Host Identity Tag (HIT) and Drone Remote ID Protocol 
(DRIP, RFC9374, `2001:30::/28`) with the DRIP Entity Tag (DET). More on ORCHIDs in general can be found in RFC7343
and its predecessor RFC4843.

This project is designed as a cross-platform (and in the future cross-language) reference implementation for
ORCHIDs. It is not intended to be a complete solution but more of a starting point and general toolbox for 
using of ORCHIDs as part of modern applications and protocols.

## Package Features

This package supports a majority of cryptographic keys that are shared between the HIT Suite ID (RFC7401) and 
HHIT Suite ID (RFC9374) families. The missing key algorithm is DSA and is excluded in favor of ECDSA. ECDSA_LOW is 
also not supported due to the underlying library missing its curve (SECP160R1).

| Key Algorithm       | Key Sizes or Curves    | Underlying Package |
|---------------------|------------------------|--------------------|
| RS256, RS384, RS512 | 2048, 4096, 8192       | `cryptography`     |
| ECDSA               | NIST P-256, NIST P-384 | `cryptography`     |
| EdDSA               | Ed25519, Ed448         | `cryptography`     |

> Note: Encryption operations are not supported under ORCHID as the cryptographic agility does not include any 
encryption key algorithms

The following structures can be obtained through the ORCHID package APIs:

| Structure                         | API                | Underlying Package | Reference            |
|-----------------------------------|--------------------|--------------------|----------------------|
| COSE_Key                          | `Orchid`           | `cwt`              | RFC9052, Section 7   |
| JWK                               | `Orchid`           | `jwcrypto`         | RFC7517              |
| COSE_Sign1                        | `ObjectSigning`    | `cwt`              | RFC9052, Section 4   |
| COSE_Sign                         | `ObjectSigning`    | `cwt`              | RFC9052, Section 4   |
| JWS                               | `ObjectSigning`    | `jwcrypto`         | RFC7515              |
| X.509 Certificate Signing Request | `x509.csr`         | `cryptography`     | -                    |
| X.509 Certificate                 | `x509.certificate` | `cryptography`     | -                    |
| DRIP Endorsement                  | `Drip`             | -                  | RFC9575, Section 4.1 |

All of these support ORCHIDs through their key algorithms for signing but also identify the public keys using ORCHIDs
in respective fields for key identification (COSE/JOSE with `kid`, X.509 with `Subject Alternative Name: IP6`).
