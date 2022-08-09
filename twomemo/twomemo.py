# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

import secrets
from typing import Optional, Tuple, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

import doubleratchet
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)
import x3dh
import x3dh.identity_key_pair

from omemo.backend import Backend, DecryptionFailed, KeyExchangeFailed
from omemo.bundle import Bundle
from omemo.identity_key_pair import IdentityKeyPair, IdentityKeyPairSeed
from omemo.message import Content, EncryptedKeyMaterial, PlainKeyMaterial, KeyExchange
from omemo.session import Initiation, Session
from omemo.storage import Storage
from omemo.types import JSONType

# https://github.com/PyCQA/pylint/issues/4987
from .schema_pb2 import (  # pylint: disable=no-name-in-module
    OMEMOAuthenticatedMessage,
    OMEMOMessage
)


__all__ = [  # pylint: disable=unused-variable
    "Twomemo",
    "TwomemoAEAD",
    "TwomemoBundle",
    "TwomemoContent",
    "TwomemoDoubleRatchet",
    "TwomemoEncryptedKeyMaterial",
    "TwomemoKeyExchange",
    "TwomemoMessageChainKDF",
    "TwomemoPlainKeyMaterial",
    "TwomemoRootChainKDF",
    "TwomemoSession",
    "TwomemoState"
]


class TwomemoRootChainKDF(kdf_hkdf.KDF):
    """
    The KDF used by Twomemo as part of the Double Ratchet's root chain.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "OMEMO Root Chain".encode("ASCII")


class TwomemoMessageChainKDF(kdf_separate_hmacs.KDF):
    """
    The KDF used by Twomemo as part of the Double Ratchet's message chain.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256


class TwomemoAEAD(aead_aes_hmac.AEAD):
    """
    The AEAD used by Twomemo as part of the Double Ratchet. While this implementation derives from
    :class:`doubleratchet.recommended.aead_aes_hmac.AEAD`, it actually doesn't use any of its code. This is
    due to a minor difference in the way the associated data is built. The derivation only has symbolic value.

    Can only be used with :class:`TwomemoDoubleRatchet`, due to the reliance on a certain structure of the
    associated data.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return "OMEMO Message Key Material".encode("ASCII")

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function().as_cryptography

        encryption_key, authentication_key, iv = cls.__derive(key, hash_function, cls._get_info())

        # Prepare PKCS#7 padded plaintext
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        aes = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = aes.update(padded_plaintext) + aes.finalize()  # pylint: disable=no-member

        # Parse the associated data
        associated_data, header = cls.__parse_associated_data(associated_data)

        # Build an OMEMOMessage including the header and the ciphertext
        omemo_message = OMEMOMessage(
            n=header.sending_chain_length,
            pn=header.previous_sending_chain_length,
            dh_pub=header.ratchet_pub,
            ciphertext=ciphertext
        ).SerializeToString(True)

        # Calculate the authentication tag over the associated data and the OMEMOMessage
        auth = hmac.HMAC(authentication_key, hash_function, backend=default_backend())
        auth.update(associated_data + omemo_message)

        # Truncate the authentication tag to 16 bytes/128 bits and serialize it with the OMEMOMessage in an
        # OMEMOAuthenticatedMessage.
        return OMEMOAuthenticatedMessage(
            mac=auth.finalize()[:16],
            message=omemo_message
        ).SerializeToString(True)

    @classmethod
    def decrypt(cls, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        hash_function = cls._get_hash_function().as_cryptography

        decryption_key, authentication_key, iv = cls.__derive(key, hash_function, cls._get_info())

        # Parse the associated data
        associated_data, header = cls.__parse_associated_data(associated_data)

        # Parse the ciphertext as an OMEMOAuthenticatedMessage
        omemo_authenticated_message = OMEMOAuthenticatedMessage.FromString(ciphertext)

        # Calculate and verify the authentication tag
        auth = hmac.HMAC(authentication_key, hash_function, backend=default_backend())
        auth.update(associated_data + omemo_authenticated_message.message)

        try:
            auth.verify(omemo_authenticated_message.mac)
        except InvalidSignature as e:
            raise doubleratchet.aead.AuthenticationFailedException() from e

        # Parse the OMEMOMessage contained in the OMEMOAuthenticatedMessage
        omemo_message = OMEMOMessage.FromString(omemo_authenticated_message.message)

        # Make sure that the headers match as a little additional consistency check
        if header != doubleratchet.Header(omemo_message.dh_pub, omemo_message.pn, omemo_message.n):
            raise doubleratchet.aead.AuthenticationFailedException("Header mismatch.")

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        try:
            aes = Cipher(
                algorithms.AES(decryption_key),
                modes.CBC(iv),
                backend=default_backend()
            ).decryptor()
            padded_plaintext = aes.update(omemo_message.ciphertext)  # pylint: disable=no-member
            padded_plaintext += aes.finalize()  # pylint: disable=no-member
        except ValueError as e:
            raise doubleratchet.aead.DecryptionFailedException("Decryption failed.") from e

        # Remove the PKCS#7 padding from the plaintext
        try:
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            raise doubleratchet.aead.DecryptionFailedException("Plaintext padded incorrectly.") from e

        return plaintext

    @staticmethod
    def __derive(key: bytes, hash_function: hashes.HashAlgorithm, info: bytes) -> Tuple[bytes, bytes, bytes]:
        # Prepare the salt, a zero-filled byte sequence with the size of the hash digest
        salt = b"\x00" * hash_function.digest_size

        # Derive 80 bytes
        hkdf_out = HKDF(
            algorithm=hash_function,
            length=80,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(key)

        # Split these 80 bytes into three parts
        return hkdf_out[:32], hkdf_out[32:64], hkdf_out[64:]

    @staticmethod
    def __parse_associated_data(associated_data: bytes) -> Tuple[bytes, doubleratchet.Header]:
        """
        Parse the associated data as built by :meth:`TwomemoDoubleRatchet._build_associated_data`.

        Args:
            associated_data: The associated data.

        Returns:
            The original associated data and the header used to build it.
        """

        associated_data, omemo_message = associated_data[:64], OMEMOMessage.FromString(associated_data[64:])
        return associated_data, doubleratchet.Header(omemo_message.dh_pub, omemo_message.pn, omemo_message.n)


class TwomemoDoubleRatchet(doubleratchet.DoubleRatchet):
    """
    The Double Ratchet used by Twomemo.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: doubleratchet.Header) -> bytes:
        return associated_data + OMEMOMessage(
            n=header.sending_chain_length,
            pn=header.previous_sending_chain_length,
            dh_pub=header.ratchet_pub
        ).SerializeToString(True)


class TwomemoState(x3dh.BaseState):
    """
    The X3DH state used by Twomemo.
    """

    @staticmethod
    def _encode_public_key(key_format: x3dh.IdentityKeyFormat, pub: bytes) -> bytes:
        return pub


class TwomemoBundle(Bundle):
    """
    :class:`~omemo.bundle.Bundle` implementation used by the :class:`Twomemo` backend implementation,
    providing OMEMO under the `urn:xmpp:omemo:2` backend.
    """

    def __init__(self, bare_jid: str, device_id: int, bundle: x3dh.Bundle) -> None:
        """
        Args:
            bare_jid: The bare JID this bundle belongs to.
            device_id: The device id of the specific device this bundle belongs to.
            bundle: The bundle to store in this instance.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__bundle = bundle

    @property
    def namespace(self) -> str:
        return "urn:xmpp:omemo:2"

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def identity_key(self) -> bytes:
        return self.__bundle.identity_key

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TwomemoBundle):
            return (
                other.bare_jid == self.bare_jid
                and other.device_id == self.device_id
                and other.bundle == self.bundle
            )

        return False

    def __hash__(self) -> int:
        return hash((self.bare_jid, self.device_id, self.bundle))

    @property
    def bundle(self) -> x3dh.Bundle:
        """
        Returns:
            The bundle held by this instance.
        """

        return self.__bundle


class TwomemoContent(Content):
    """
    :class:`~omemo.message.Content` implementation used by the :class:`Twomemo` backend implementation,
    providing OMEMO under the `urn:xmpp:omemo:2` backend.
    """

    def __init__(self, ciphertext: bytes) -> None:
        """
        Args:
            ciphertext: The ciphertext to store in this instance.

        Note:
            For empty OMEMO messages as per the specification, the ciphertext is set to an empty byte string.
        """

        self.__ciphertext = ciphertext

    @property
    def ciphertext(self) -> bytes:
        """
        Returns:
            The ciphertext held by this instance.
        """

        return self.__ciphertext

    @property
    def empty(self) -> bool:
        """
        Returns:
            Whether this instance corresponds to an empty OMEMO message.
        """

        return self.__ciphertext == b""


class TwomemoEncryptedKeyMaterial(EncryptedKeyMaterial):
    """
    :class:`~omemo.message.EncryptedKeyMaterial` implementation used by the :class:`Twomemo` backend
    implementation, providing OMEMO under the `urn:xmpp:omemo:2` backend.
    """

    def __init__(
        self,
        bare_jid: str,
        device_id: int,
        encrypted_message: doubleratchet.EncryptedMessage
    ) -> None:
        """
        Args:
            bare_jid: The bare JID of the other party.
            device_id: The device id of the specific device of the other party.
            encrypted_message: The encrypted Double Ratchet message to store in this instance.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__encrypted_message = encrypted_message

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def encrypted_message(self) -> doubleratchet.EncryptedMessage:
        """
        Returns:
            The encrypted Double Ratchet message held by this instance.
        """

        return self.__encrypted_message


class TwomemoPlainKeyMaterial(PlainKeyMaterial):
    """
    :class:`~omemo.message.PlainKeyMaterial` implementation used by the :class:`Twomemo` backend
    implementation, providing OMEMO under the `urn:xmpp:omemo:2` backend.
    """

    def __init__(self, key: bytes, auth_tag: bytes) -> None:
        """
        Args:
            key: The key to store in this instance.
            auth_tag: The authentication tag to store in this instance.

        Note:
            For empty OMEMO messages as per the specification, the key is set to 32 zero-bytes, and the auth
            tag is set to an empty byte string.
        """

        self.__key = key
        self.__auth_tag = auth_tag

    @property
    def key(self) -> bytes:
        """
        Returns:
            The key held by this instance.
        """

        return self.__key

    @property
    def auth_tag(self) -> bytes:
        """
        Returns:
            The authentication tag held by this instance.
        """

        return self.__auth_tag

    @property
    def empty(self) -> bool:
        """
        Returns:
            Whether this instance corresponds to an empty OMEMO message.
        """

        return self.__key == b"\x00" * 32 and self.__auth_tag == b""


class TwomemoKeyExchange(KeyExchange):
    """
    :class:`~omemo.message.KeyExchange` implementation used by the :class:`Twomemo` backend implementation,
    providing OMEMO under the `urn:xmpp:omemo:2` backend.
    """

    def __init__(self, header: x3dh.Header) -> None:
        """
        Args:
            header: The header to store in this instance.
        """

        self.__header = header

    @property
    def identity_key(self) -> bytes:
        return self.__header.identity_key

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TwomemoKeyExchange):
            return other.header == self.header

        return False

    def __hash__(self) -> int:
        return hash(self.header)

    @property
    def header(self) -> x3dh.Header:
        """
        Returns:
            The header held by this instance.
        """

        return self.__header


class TwomemoSession(Session):
    """
    :class:`~omemo.session.Session` implementation used by the :class:`Twomemo` backend implementation,
    providing OMEMO under the `urn:xmpp:omemo:2` namespace.

    This implementation models the session type as a simple storage type.
    """

    def __init__(
        self,
        bare_jid: str,
        device_id: int,
        initiation: Initiation,
        key_exchange: TwomemoKeyExchange,
        associated_data: bytes,
        double_ratchet: TwomemoDoubleRatchet,
        confirmed: bool = False
    ):
        """
        Args:
            bare_jid: The bare JID of the other party.
            device_id: The device id of the specific device of the other party.
            initiation: Whether this session was built through active or passive session initiation.
            key_exchange: The key exchange information to store in this instance.
            associated_data: The associated data to store in this instance.
            double_ratchet: The Double Ratchet to store in this instance.
            confirmed: Whether the session was confirmed, i.e. whether a message was decrypted after actively
                initiating the session. Leave this at the default value for passively initiated sessions.
        """

        self.__bare_jid = bare_jid
        self.__device_id = device_id
        self.__initiation = initiation
        self.__key_exchange = key_exchange
        self.__associated_data = associated_data
        self.__double_ratchet = double_ratchet
        self.__confirmed = confirmed

    @property
    def namespace(self) -> str:
        return "urn:xmpp:omemo:2"

    @property
    def bare_jid(self) -> str:
        return self.__bare_jid

    @property
    def device_id(self) -> int:
        return self.__device_id

    @property
    def initiation(self) -> Initiation:
        return self.__initiation

    @property
    def confirmed(self) -> bool:
        return self.__confirmed

    @property
    def key_exchange(self) -> TwomemoKeyExchange:
        return self.__key_exchange

    @property
    def receiving_chain_length(self) -> Optional[int]:
        return self.__double_ratchet.receiving_chain_length

    @property
    def sending_chain_length(self) -> int:
        return self.__double_ratchet.sending_chain_length

    @property
    def associated_data(self) -> bytes:
        """
        Returns:
            The associated data held by this instance.
        """

        return self.__associated_data

    @property
    def double_ratchet(self) -> TwomemoDoubleRatchet:
        """
        Returns:
            The Double Ratchet held by this instance.
        """

        return self.__double_ratchet

    def confirm(self) -> None:
        """
        Mark this session as confirmed.
        """

        self.__confirmed = True


class Twomemo(Backend):
    """
    :class:`~omemo.backend.Backend` implementation providing OMEMO in the `urn:xmpp:omemo:2` namespace.
    """

    def __init__(
        self,
        storage: Storage,
        max_num_per_session_skipped_keys: int = 1000,
        max_num_per_message_skipped_keys: Optional[int] = None
    ) -> None:
        """
        Args:
            storage: The storage to store backend-specific data in. Note that all data keys are prefixed with
                the backend namespace to avoid name clashes between backends.
            max_num_per_session_skipped_keys: The maximum number of skipped message keys to keep around per
                session. Once the maximum is reached, old message keys are deleted to make space for newer
                ones. Accessible via :attr:`max_num_per_session_skipped_keys`.
            max_num_per_message_skipped_keys: The maximum number of skipped message keys to accept in a single
                message. When set to ``None`` (the default), this parameter defaults to the per-session
                maximum (i.e. the value of the ``max_num_per_session_skipped_keys`` parameter). This parameter
                may only be 0 if the per-session maximum is 0, otherwise it must be a number between 1 and the
                per-session maximum. Accessible via :attr:`max_num_per_message_skipped_keys`.
        """

        super().__init__(max_num_per_session_skipped_keys, max_num_per_message_skipped_keys)

        self.__storage = storage

    async def __get_state(self) -> TwomemoState:
        """
        Returns:
            The loaded or newly created X3DH state.
        """

        def check_type(value: JSONType) -> x3dh.types.JSONObject:
            if isinstance(value, dict):
                return cast(x3dh.types.JSONObject, value)

            raise TypeError(
                f"Stored TwomemoState under key /{self.namespace}/x3dh corrupt: not a JSON object: {value}"
            )

        state, _ = (await self.__storage.load(
            f"/{self.namespace}/x3dh"
        )).fmap(check_type).fmap(lambda serialized: TwomemoState.from_json(
            serialized,
            x3dh.IdentityKeyFormat.ED_25519,
            x3dh.HashFunction.SHA_256,
            "OMEMO X3DH".encode("ASCII")
        )).maybe((None, False))

        if state is None:
            identity_key_pair = await IdentityKeyPair.get(self.__storage)

            state = TwomemoState.create(
                x3dh.IdentityKeyFormat.ED_25519,
                x3dh.HashFunction.SHA_256,
                "OMEMO X3DH".encode("ASCII"),
                (
                    x3dh.identity_key_pair.IdentityKeyPairSeed(identity_key_pair.seed)
                    if isinstance(identity_key_pair, IdentityKeyPairSeed)
                    else x3dh.identity_key_pair.IdentityKeyPairPriv(identity_key_pair.as_priv().priv)
                )
            )

            await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return state

    @property
    def namespace(self) -> str:
        return "urn:xmpp:omemo:2"

    async def load_session(self, bare_jid: str, device_id: int) -> Optional[TwomemoSession]:
        def check_type(value: JSONType) -> doubleratchet.types.JSONObject:
            if isinstance(value, dict):
                return cast(doubleratchet.types.JSONObject, value)

            raise TypeError(
                f"Stored TwomemoDoubleRatchet under key"
                f" /{self.namespace}/{bare_jid}/{device_id}/double_ratchet corrupt: not a JSON object:"
                f" {value}"
            )

        try:
            double_ratchet = (await self.__storage.load(
                f"/{self.namespace}/{bare_jid}/{device_id}/double_ratchet"
            )).fmap(check_type).fmap(lambda serialized: TwomemoDoubleRatchet.from_json(
                serialized,
                diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
                TwomemoRootChainKDF,
                TwomemoMessageChainKDF,
                b"\x02\x01",
                self.max_num_per_message_skipped_keys,
                self.max_num_per_session_skipped_keys,
                TwomemoAEAD
            )).maybe(None)
        except doubleratchet.InconsistentSerializationException:
            return None

        if double_ratchet is None:
            return None

        initiation = Initiation((await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/initiation",
            str
        )).from_just())

        identity_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/identity_key"
        )).from_just()

        ephemeral_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/ephemeral_key"
        )).from_just()

        signed_pre_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key"
        )).from_just()

        pre_key = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key"
        )).maybe(None)

        associated_data = (await self.__storage.load_bytes(
            f"/{self.namespace}/{bare_jid}/{device_id}/associated_data"
        )).from_just()

        confirmed = (await self.__storage.load_primitive(
            f"/{self.namespace}/{bare_jid}/{device_id}/confirmed",
            bool
        )).from_just()

        return TwomemoSession(bare_jid, device_id, initiation, TwomemoKeyExchange(
            x3dh.Header(identity_key, ephemeral_key, signed_pre_key, pre_key)
        ), associated_data, double_ratchet, confirmed)

    async def store_session(self, session: Session) -> None:
        assert isinstance(session, TwomemoSession)

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/initiation",
            session.initiation.name
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/identity_key",
            session.key_exchange.header.identity_key
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/ephemeral_key",
            session.key_exchange.header.ephemeral_key
        )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/signed_pre_key",
            session.key_exchange.header.signed_pre_key
        )

        if session.key_exchange.header.pre_key is None:
            await self.__storage.delete(
                f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key"
            )
        else:
            await self.__storage.store_bytes(
                f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key",
                session.key_exchange.header.pre_key
            )

        await self.__storage.store_bytes(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/associated_data",
            session.associated_data
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/double_ratchet",
            session.double_ratchet.json
        )

        await self.__storage.store(
            f"/{self.namespace}/{session.bare_jid}/{session.device_id}/confirmed",
            session.confirmed
        )

        # Keep track of bare JIDs with stored sessions
        bare_jids = set((await self.__storage.load_list(f"/{self.namespace}", str)).maybe([]))
        bare_jids.add(session.bare_jid)
        await self.__storage.store(f"/{self.namespace}", list(bare_jids))

        # Keep track of device ids with stored sessions
        device_ids = set((await self.__storage.load_list(
            f"/{self.namespace}/{session.bare_jid}",
            int
        )).maybe([]))
        device_ids.add(session.device_id)
        await self.__storage.store(f"/{self.namespace}/{session.bare_jid}", list(device_ids))

    async def build_session_active(
        self,
        bare_jid: str,
        device_id: int,
        bundle: Bundle,
        plain_key_material: PlainKeyMaterial
    ) -> Tuple[TwomemoSession, TwomemoEncryptedKeyMaterial]:
        assert isinstance(bundle, TwomemoBundle)
        assert isinstance(plain_key_material, TwomemoPlainKeyMaterial)

        try:
            shared_secret, associated_data, header = (await self.__get_state()).get_shared_secret_active(
                bundle.bundle
            )
        except x3dh.KeyAgreementException as e:
            raise KeyExchangeFailed() from e

        double_ratchet, encrypted_message = TwomemoDoubleRatchet.encrypt_initial_message(
            diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
            TwomemoRootChainKDF,
            TwomemoMessageChainKDF,
            b"\x02\x01",
            self.max_num_per_message_skipped_keys,
            self.max_num_per_session_skipped_keys,
            TwomemoAEAD,
            shared_secret,
            bundle.bundle.signed_pre_key,
            plain_key_material.key + plain_key_material.auth_tag,
            associated_data
        )

        session = TwomemoSession(
            bare_jid,
            device_id,
            Initiation.ACTIVE,
            TwomemoKeyExchange(header),
            associated_data,
            double_ratchet
        )

        encrypted_key_material = TwomemoEncryptedKeyMaterial(bare_jid, device_id, encrypted_message)

        return session, encrypted_key_material

    async def build_session_passive(
        self,
        bare_jid: str,
        device_id: int,
        key_exchange: KeyExchange,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> Tuple[TwomemoSession, TwomemoPlainKeyMaterial]:
        assert isinstance(key_exchange, TwomemoKeyExchange)
        assert isinstance(encrypted_key_material, TwomemoEncryptedKeyMaterial)

        state = await self.__get_state()

        try:
            shared_secret, associated_data, signed_pre_key = state.get_shared_secret_passive(
                key_exchange.header
            )
        except x3dh.KeyAgreementException as e:
            raise KeyExchangeFailed() from e

        try:
            double_ratchet, decrypted_message = TwomemoDoubleRatchet.decrypt_initial_message(
                diffie_hellman_ratchet_curve25519.DiffieHellmanRatchet,
                TwomemoRootChainKDF,
                TwomemoMessageChainKDF,
                b"\x02\x01",
                self.max_num_per_message_skipped_keys,
                self.max_num_per_session_skipped_keys,
                TwomemoAEAD,
                shared_secret,
                signed_pre_key.priv,
                encrypted_key_material.encrypted_message,
                associated_data
            )
        except Exception as e:
            raise DecryptionFailed(
                "Decryption of the initial message as part of passive session building failed."
            ) from e

        session = TwomemoSession(
            bare_jid,
            device_id,
            Initiation.PASSIVE,
            key_exchange,
            associated_data,
            double_ratchet
        )

        plain_key_material = TwomemoPlainKeyMaterial(decrypted_message[:32], decrypted_message[32:])

        return session, plain_key_material

    async def encrypt_plaintext(self, plaintext: bytes) -> Tuple[TwomemoContent, TwomemoPlainKeyMaterial]:
        # Generate 32 bytes of cryptographically secure random data for the key
        key = secrets.token_bytes(32)

        # Derive 80 bytes from the key using HKDF-SHA-256
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=80,
            salt=b"\x00" * 32,
            info="OMEMO Payload".encode("ASCII"),
            backend=default_backend()
        ).derive(key)

        # Split those 80 bytes into an encryption key, authentication key and an initialization vector
        encryption_key = key_material[:32]
        authentication_key = key_material[32:64]
        initialization_vector = key_material[64:]

        # Prepare PKCS#7 padded plaintext
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        aes = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(initialization_vector),
            backend=default_backend()
        ).encryptor()
        ciphertext = aes.update(padded_plaintext) + aes.finalize()  # pylint: disable=no-member

        # Calculate the authentication tag
        auth = hmac.HMAC(authentication_key, hashes.SHA256(), backend=default_backend())
        auth.update(ciphertext)

        # Truncate the authentication tag to 16 bytes/128 bits
        auth_tag = auth.finalize()[:16]

        return TwomemoContent(ciphertext), TwomemoPlainKeyMaterial(key, auth_tag)

    async def encrypt_empty(self) -> Tuple[TwomemoContent, TwomemoPlainKeyMaterial]:
        return TwomemoContent(b""), TwomemoPlainKeyMaterial(b"\x00" * 32, b"")

    async def encrypt_key_material(
        self,
        session: Session,
        plain_key_material: PlainKeyMaterial
    ) -> TwomemoEncryptedKeyMaterial:
        assert isinstance(session, TwomemoSession)
        assert isinstance(plain_key_material, TwomemoPlainKeyMaterial)

        return TwomemoEncryptedKeyMaterial(
            session.bare_jid,
            session.device_id,
            session.double_ratchet.encrypt_message(
                plain_key_material.key + plain_key_material.auth_tag,
                session.associated_data
            )
        )

    async def decrypt_plaintext(self, content: Content, plain_key_material: PlainKeyMaterial) -> bytes:
        assert isinstance(content, TwomemoContent)
        assert isinstance(plain_key_material, TwomemoPlainKeyMaterial)

        # Derive 80 bytes from the key using HKDF-SHA-256
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=80,
            salt=b"\x00" * 32,
            info="OMEMO Payload".encode("ASCII"),
            backend=default_backend()
        ).derive(plain_key_material.key)

        # Split those 80 bytes into an encryption key, authentication key and an initialization vector
        decryption_key = key_material[:32]
        authentication_key = key_material[32:64]
        initialization_vector = key_material[64:]

        # Calculate and verify the authentication tag
        new_auth = hmac.HMAC(authentication_key, hashes.SHA256(), backend=default_backend())
        new_auth.update(content.ciphertext)
        try:
            new_auth.verify(plain_key_material.auth_tag)
        except InvalidSignature as e:
            raise DecryptionFailed("Authentication tag verification failed.") from e

        # Decrypt the plaintext using AES-256 (the 256 bit are implied by the key size) in CBC mode and the
        # previously created key and IV
        aes = Cipher(
            algorithms.AES(decryption_key),
            modes.CBC(initialization_vector),
            backend=default_backend()
        ).decryptor()
        try:
            padded_plaintext = aes.update(content.ciphertext) + aes.finalize()  # pylint: disable=no-member
        except ValueError as e:
            raise DecryptionFailed("Ciphertext decryption failed.") from e

        # Remove the PKCS#7 padding from the plaintext
        unpadder = PKCS7(128).unpadder()
        try:
            return unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            raise DecryptionFailed("Plaintext unpadding failed.") from e

    async def decrypt_key_material(
        self,
        session: Session,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> TwomemoPlainKeyMaterial:
        assert isinstance(session, TwomemoSession)
        assert isinstance(encrypted_key_material, TwomemoEncryptedKeyMaterial)

        try:
            decrypted_message = session.double_ratchet.decrypt_message(
                encrypted_key_material.encrypted_message,
                session.associated_data
            )
        except Exception as e:
            raise DecryptionFailed("Key material decryption failed.") from e

        session.confirm()

        return TwomemoPlainKeyMaterial(decrypted_message[:32], decrypted_message[32:])

    async def signed_pre_key_age(self) -> int:
        return (await self.__get_state()).signed_pre_key_age()

    async def rotate_signed_pre_key(self) -> None:
        state = await self.__get_state()

        state.rotate_signed_pre_key()

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def hide_pre_key(self, session: Session) -> bool:
        assert isinstance(session, TwomemoSession)

        hidden = False

        if session.key_exchange.header.pre_key is not None:
            state = await self.__get_state()

            hidden = state.hide_pre_key(session.key_exchange.header.pre_key)

            await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return hidden

    async def delete_pre_key(self, session: Session) -> bool:
        assert isinstance(session, TwomemoSession)

        deleted = False

        if session.key_exchange.header.pre_key is not None:
            state = await self.__get_state()

            deleted = state.delete_pre_key(session.key_exchange.header.pre_key)

            await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

        return deleted

    async def delete_hidden_pre_keys(self) -> None:
        state = await self.__get_state()

        state.delete_hidden_pre_keys()

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def get_num_visible_pre_keys(self) -> int:
        return (await self.__get_state()).get_num_visible_pre_keys()

    async def generate_pre_keys(self, num_pre_keys: int) -> None:
        state = await self.__get_state()

        state.generate_pre_keys(num_pre_keys)

        await self.__storage.store(f"/{self.namespace}/x3dh", state.json)

    async def get_bundle(self, bare_jid: str, device_id: int) -> TwomemoBundle:
        return TwomemoBundle(bare_jid, device_id, (await self.__get_state()).bundle)

    async def purge(self) -> None:
        for bare_jid in (await self.__storage.load_list(f"/{self.namespace}", str)).maybe([]):
            await self.purge_bare_jid(bare_jid)

        await self.__storage.delete(f"/{self.namespace}")
        await self.__storage.delete(f"/{self.namespace}/x3dh")

    async def purge_bare_jid(self, bare_jid: str) -> None:
        storage = self.__storage

        for device_id in (await storage.load_list(f"/{self.namespace}/{bare_jid}", int)).maybe([]):
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/initiation")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/identity_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/ephemeral_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/signed_pre_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/key_exchange/pre_key")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/associated_data")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/double_ratchet")
            await storage.delete(f"/{self.namespace}/{bare_jid}/{device_id}/confirmed")

        await storage.delete(f"/{self.namespace}/{bare_jid}")

        bare_jids = set((await storage.load_list(f"/{self.namespace}", str)).maybe([]))
        bare_jids.remove(bare_jid)
        await storage.store(f"/{self.namespace}", list(bare_jids))
