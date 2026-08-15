from copy import deepcopy
from ipaddress import IPv6Address
from typing import get_args

from cwt import COSEMessage, COSE, VerifyError, DecodeError
from cwt.cose_key_interface import COSEKeyInterface
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from pyblossom.crypto import OrchidRsaAlgorithms
from pyblossom.orchid import Orchid


class ObjectSigning:
    """Container for COSE/JOSE signature structure generation & verification.

    Internally uses a dict of Orchid instances, indexed by ORCHID IPv6 addresses.
    Orchids can be added or removed using their respective ORCHID IPv6 address (Key ID).
    Allows selection of subset of internally stored Orchid instances to use for signing operations.

    WARNING: this class and its functions have not been tested. Beware of dragons!
    """
    def __init__(self):
        self._signers: dict[IPv6Address, Orchid] = {}

    def add_signer(self, signer: Orchid) -> None:
        self._signers.update({signer.ip: signer})

    def add_signers(self, signers: list[Orchid] | dict[IPv6Address, Orchid]) -> None:
        if isinstance(signers, dict):
            if not all(isinstance(k, IPv6Address) and isinstance(v, Orchid) for k, v in signers.items()):
                raise ValueError("mixed key/value types in signers: must be IPv6Address: Orchid")
            self._signers.update(signers)
        else:
            for signer in signers: self.add_signer(signer)

    def remove_signer(self, kid: str | bytes | IPv6Address) -> None:
        try:
            _kid = IPv6Address(kid) if not isinstance(kid, IPv6Address) else kid
            if _kid in self._signers: self._signers.pop(_kid)
        except ValueError:
            raise ValueError("kid is not IPv6Address")

    def remove_signers(self, kids: list[str | bytes | IPv6Address]) -> None:
        for kid in kids: self.remove_signer(kid)

    def get_signer(
            self,
            kid: IPv6Address,
            json: bool = False,
            alg: OrchidRsaAlgorithms = 'PS256'
    ) -> JWK | COSEKeyInterface:
        """
        Provides an Orchid instance from the internal store as COSE Key or JWK.

        Args:
            kid: ORCHID IPv6 address to select
            json: flag for JWK or COSE Key, default=COSE Key (False)
            alg: selection for RSA algorithm, default=PS256

        Returns:
            Instance of JWK or COSE Key
        """
        if json:
            return self._signers[kid].jwk(True, alg)
        else:
            return self._signers[kid].cose_key(True, alg)

    def sign(
            self,
            payload: bytes,
            signers: dict[str | bytes | IPv6Address, OrchidRsaAlgorithms],
            json: bool = False
    ) -> JWS | COSEMessage:
        """
        Creates a JWS or COSE Message instance that is signed by selected Orchids.

        Args:
            payload: data bytes to be signed
            signers: map of internal Orchids (using Key ID) from store and the RSA algorithm to use
            json: flag for JSON Web Signature or COSE Sign/Sign1

        Returns:
            Instance of JWS or COSE Message with Sign/Sign1
        """
        _signers = self._prepare_signers(signers, json)
        if len(_signers) == 0: raise ValueError("no valid signers")
        if json:
            _jws = JWS()
            for signer in _signers: _jws.add_signature(signer, signer['alg'], payload)
            return _jws
        else:
            _cose = COSE.new(True, True)
            if len(_signers) == 1:
                _msg = _cose.encode_and_sign(payload, _signers[0])
            else:
                _msg = _cose.encode_and_sign(payload, signers=_signers)
            return COSEMessage.loads(_msg)

    def countersign(
            self,
            msg: COSEMessage,
            signers: dict[str | bytes | IPv6Address, OrchidRsaAlgorithms]
    ) -> COSEMessage:
        """

        Args:
            msg: COSE Message to countersign
            signers: map of internal Orchids (using Key ID) from store and the RSA algorithm to use

        Returns:
            copy of COSE Message countersigned
        """
        _msg = deepcopy(msg)
        for signer in self._prepare_signers(signers): _msg.countersign(signer)
        return _msg

    def verify(
            self,
            token: str | bytes,
            keys: dict[str | bytes | IPv6Address, OrchidRsaAlgorithms]
    ) -> tuple[bool, JWS | COSEMessage | None]:
        """
        WARNING: not tested, probably very very very very wrong and broken.

        Args:
            token:
            keys:

        Returns:

        """
        _keys = self._prepare_signers(keys) if isinstance(token, bytes) else self._prepare_signers(keys, True)
        if isinstance(token, bytes):
            try:
                _msg = COSEMessage.loads(token)
            except ValueError | DecodeError | VerifyError:
                return False, None
            try:
                _ = COSE.new().decode(token, _keys)
                return True, _msg
            except ValueError | DecodeError | VerifyError:
                return False, _msg
        else:
            return False, None  # todo: support

    def _prepare_signers(
            self,
            signers: dict[str | bytes | IPv6Address, OrchidRsaAlgorithms],
            json: bool = False
    ) -> list[JWK] | list[COSEKeyInterface]:
        _signers = []
        for _kid, _alg in signers.items():
            if isinstance(_kid, str) or isinstance(_kid, bytes):
                try:
                    __kid = IPv6Address(_kid)
                except ValueError:
                    continue
            else:
                __kid = _kid
            if __kid not in self._signers: continue
            if not self._signers[__kid].has_private: continue
            if _alg not in get_args(OrchidRsaAlgorithms): continue
            _alg: OrchidRsaAlgorithms
            _signers.append(self.get_signer(__kid, json, _alg))
        return _signers
