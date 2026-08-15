# Overlay Routable Cryptographic Hash IDentifier (ORCHID)

ORCHIDs are valid non-routable addresses that are formed under specific IANA assigned prefixes out of the IPv6 
Special Purpose Address Space. They encode directly cryptographic agility and optional additional information
(such as hierarchy) while acting as a handle to the public portion of an asymmetric keypair.

The main protocols using ORCHIDs, with dedicated IPv6 prefixes, are the Host Identity Protocol 
(HIP, RFC9063, `2001:20::/28`) in form of the Host Identity Tag (HIT) and Drone Remote ID Protocol 
(DRIP, RFC9434, `2001:30::/28`) with the DRIP Entity Tag (DET).

## Package Features

| Key Algorithm       | Key Sizes or Curves    |
|---------------------|------------------------|
| RS256, RS384, RS512 | 2048, 4096, 8192       |
| ECDSA               | NIST P-256, NIST P-384 |
| EdDSA               | Ed25519, Ed448         |

> Note: Encryption operations are not supported under ORCHID as the cryptographic agility does not include any 
encryption key algorithms

The following structures can be obtained through the ORCHID package APIs:

| Structure                         | API      | Underlying Package | Reference            |
|-----------------------------------|----------|--------------------|----------------------|
| COSE_Sign1                        | `ObjectSigning`   | `cwt`              | RFC9052, Section 4   |
| COSE_Sign                         | `ObjectSigning`   | `cwt`              | RFC9052, Section 4   |
| COSE_Key                          | `Orchid` | `cwt`              | RFC9052, Section 7   |
| JWS                               | `Jose`   | `jwcrypto`         | RFC7515              |
| JWK                               | `Orchid` | `jwcrypto`         | RFC7517              |
| X.509 Certificate Signing Request | `X509`   | `cryptography`     | -                    |
| X.509 Certificate                 | `X509`   | `cryptography`     | -                    |
| DRIP Endorsement                  | `Drip`   | -                  | RFC9575, Section 4.1 |

All of these support ORCHIDs through their key algorithms for signing but also identify the public keys using ORCHIDs
in respective fields for key identification (COSE/JOSE with `kid`, X.509 with `Subject Alternative Name: IP6`).
