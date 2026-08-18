from copy import deepcopy
from ipaddress import IPv6Address
from typing import get_args

from cwt import COSEMessage, COSE, VerifyError, DecodeError
from cwt.cose_key_interface import COSEKeyInterface
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from orchis.crypto import OrchisAlgorithm
from orchis.orchid import Orchid


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
        """
        Adds an Orchid instance to the internal store.

        Args:
            signer: Orchid instance.

        Returns:
            None
        """
        self._signers.update({signer.ip: signer})

    def add_signers(self, signers: list[Orchid] | dict[IPv6Address, Orchid]) -> None:
        """
        Adds a list of Orchids or dict of Orchids, indexed by ORCHID IPv6 addresses.

        This function confirms that the dict input type is properly formed with IPv6 addresses as
        keys and Orchid instances as values.

        The list input uses the Orchids ip attribute as the key for the internal store.

        Args:
            signers: list of Orchid instances or dict w/IPv6 addresses as key and Orchid instances as value

        Returns:
            None
        """
        if isinstance(signers, dict):
            if not all(isinstance(k, IPv6Address) and isinstance(v, Orchid) for k, v in signers.items()):
                raise ValueError("mixed key/value types in signers: must be {IPv6Address: Orchid}")
            self._signers.update(signers)
        else:
            for signer in signers: self.add_signer(signer)

    def remove_signer(self, ip6: str | bytes | IPv6Address) -> bool:
        """
        Attempts to remove Orchid instance from store based on key.

        Will attempt to translate input parameter to IPv6Address.

        Args:
            ip6: ORCHID IPv6 address as str, bytes or instance of IPv6Address

        Returns:
            bool
        """
        try:
            _kid = IPv6Address(ip6) if not isinstance(ip6, IPv6Address) else ip6
            if _kid in self._signers:
                self._signers.pop(_kid)
                return True
            return False
        except ValueError:
            return False

    def remove_signers(self, ip6_list: list[str | bytes | IPv6Address]) -> None:
        for kid in ip6_list: self.remove_signer(kid)

    def get_signer(
            self,
            ip6: IPv6Address,
            jwk: bool = False,
            alg: OrchisAlgorithm = 'PS256'
    ) -> JWK | COSEKeyInterface:
        """
        Provides an Orchid instance from the internal store as COSE Key or JWK.

        Args:
            ip6: ORCHID IPv6 address to select
            jwk: flag for JWK or COSE Key, default=COSE Key (False)
            alg: selection for RSA algorithm, default=PS256

        Returns:
            Instance of JWK or COSE Key
        """
        if jwk:
            return self._signers[ip6].jwk(True, alg)
        else:
            return self._signers[ip6].cose_key(True, alg)

    def sign(
            self,
            payload: bytes,
            signers: dict[str | bytes | IPv6Address, OrchisAlgorithm],
            jws: bool = False
    ) -> JWS | COSEMessage:
        """
        Creates a JWS or COSE Message instance that is signed by selected Orchids.

        Args:
            payload: data bytes to be signed
            signers: map of Orchids (using Key ID) from store to select and the RSA algorithm to use
            jws: flag for JSON Web Signature or COSE Sign/Sign1

        Returns:
            Instance of JWS or COSE Message with Sign/Sign1
        """
        _signers = self._prepare_signers(signers, jws)
        if len(_signers) == 0: raise ValueError("no valid signers")
        if jws:
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
            signers: dict[str | bytes | IPv6Address, OrchisAlgorithm]
    ) -> COSEMessage:
        """

        Args:
            msg: COSE Message to countersign
            signers: map of Orchids (using Key ID) from store to select and the RSA algorithm to use

        Returns:
            copy of COSE Message countersigned
        """
        _msg = deepcopy(msg)
        for signer in self._prepare_signers(signers): _msg.countersign(signer)
        return _msg

    def verify(
            self,
            token: str | bytes,
            keys: dict[str | bytes | IPv6Address, OrchisAlgorithm]
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
            signers: dict[str | bytes | IPv6Address, OrchisAlgorithm],
            jwk: bool = False
    ) -> list[JWK] | list[COSEKeyInterface]:
        """
        Converts dict key to IPv6 to find Orchid in store, confirms valid RSA Algorithm
        for Orchid then convert Orchid to JWK or COSE Key.

        Any key that can not be converted to IPv6Address, any key this not found in store, any Orchid that does
        not have a private key set and any key that requests an invalid RSA Algorithm is ignored.

        Args:
            signers: map of Orchids (using Key ID) from store to select and the RSA algorithm to use
            jwk: flag for JWK or COSE Key, default=COSE Key (False)

        Returns:
            List of JWK or COSE Keys
        """
        _signers = []
        for _ip6, _alg in signers.items():
            if isinstance(_ip6, str) or isinstance(_ip6, bytes):
                try:
                    _kid = IPv6Address(_ip6)
                except ValueError:
                    continue
            else:
                _kid = _ip6
            if _kid not in self._signers: continue
            if not self._signers[_kid].has_private: continue
            if _alg not in get_args(OrchisAlgorithm): continue
            _alg: OrchisAlgorithm
            _signers.append(self.get_signer(_kid, jwk, _alg))
        return _signers
