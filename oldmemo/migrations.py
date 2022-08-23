# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
import base64
from typing import Awaitable, Callable, Dict, List, Optional, Set
from typing_extensions import TypedDict

import doubleratchet
import omemo
from omemo.session import Initiation
import x3dh
import x3dh.migrations
import x3dh.types
import xeddsa

from .oldmemo import NAMESPACE, BundleImpl, StateImpl


__all__ = [  # pylint: disable=unused-variable
    "OwnData",
    "Trust",
    "Session",
    "BoundOTPK",
    "StateSuper",
    "State",
    "LegacyStorage",
    "migrate"
]


class OwnData(TypedDict):
    # pylint: disable=invalid-name
    """
    This TypedDict describes how the own data was expected to be returned by the corresponding legacy storage
    method.
    """

    own_bare_jid: str
    own_device_id: int


class Trust(TypedDict):
    # pylint: disable=invalid-name
    """
    This TypedDict describes how trust information was expected to be returned by the corresponding legacy
    storage method.
    """

    key: str
    trusted: bool


class Session(TypedDict):
    # pylint: disable=invalid-name
    """
    This TypedDict describes how session instances (more precisely ``ExtendedDoubleRatchet`` instances) were
    serialized in the pre-stable serialization format.
    """

    super: doubleratchet.JSONObject
    other_ik: str


class BoundOTPK(TypedDict):
    # pylint: disable=invalid-name
    """
    Used as part of the legacy state format to represent a bound pre key.
    """

    otpk: str
    id: int


class StateSuper(TypedDict):
    # pylint: disable=invalid-name
    """
    Used as part of the legacy state format to represent the super class of the ``X3DHDoubleRatchet``.
    """

    super: x3dh.JSONObject
    spk_id: int
    spk_pub: Optional[str]
    otpk_id_counter: int
    otpk_ids: Dict[str, int]


class State(TypedDict):
    # pylint: disable=invalid-name
    """
    This TypedDict describes how the state (more precisely ``X3DHDoubleRatchet``) was serialized in the
    pre-stable serialization format. Note that the ``pk_messages`` entry has been omitted from this type since
    it is not needed for migration. The same applies to the ``version`` field, which apparently never had any
    relevance.
    """

    super: StateSuper
    bound_otpks: Dict[str, Dict[int, BoundOTPK]]


class LegacyStorage(ABC):
    # pylint: disable=invalid-name
    """
    This is a slightly modified copy of the storage interface used by legacy (i.e. pre-1.0.0) python-omemo.
    All methods related to storing values have been removed. A few methods for deleting values have been added
    instead. Methods related to efficient bulk loading have been removed as well.
    """

    @abstractmethod
    async def loadOwnData(self) -> Optional[OwnData]:
        """
        Returns:
            The own data stored in this instance, if any.
        """

    @abstractmethod
    async def deleteOwnData(self) -> None:
        """
        Delete the own data stored in this instance, if any. Do not raise if there is none.
        """

    @abstractmethod
    async def loadState(self) -> Optional[State]:
        """
        Returns:
            The state stored in this instance, if any.
        """

    @abstractmethod
    async def deleteState(self) -> None:
        """
        Delete the state stored in this instance, if any. Do not raise if there is none.
        """

    @abstractmethod
    async def loadSession(self, bare_jid: str, device_id: int) -> Optional[Session]:
        """
        Args:
            bare_jid: The bare JID.
            device_id: The device id.

        Returns:
            The session stored in this instance for the given bare JID + device id, if any.
        """

    @abstractmethod
    async def deleteSession(self, bare_jid: str, device_id: int) -> None:
        """
        Delete the session stored in this instance for the given bare JID + device id, if any. Do not raise if
        there is none.

        Args:
            bare_jid: The bare JID.
            device_id: The device id.
        """

    @abstractmethod
    async def loadActiveDevices(self, bare_jid: str) -> Optional[List[int]]:
        """
        Args:
            bare_jid: The bare JID.

        Returns:
            The list of active devices stored in this instance for the given bare JID, if any.

        Note:
            It doesn't matter whether you return ``None`` or an empty list of no list is stored for this bare
            JID.
        """

    @abstractmethod
    async def loadInactiveDevices(self, bare_jid: str) -> Optional[Dict[int, int]]:
        """
        Args:
            bare_jid: The bare JID.

        Returns:
            A mapping of inactive devices stored in this instance for the given bare JID, if any. The mapping
            maps from device id to the timestamp of last activity (seconds since epoch).

        Note:
            It doesn't matter whether you return ``None`` or an empty dictionary of no dictionary is stored
            for this bare JID.
        """

    @abstractmethod
    async def deleteActiveDevices(self, bare_jid: str) -> None:
        """
        Delete the list of active devices stored in this instance for the given bare JID, if any. Do not raise
        if there is none.

        Args:
            bare_jid: The bare JID.
        """

    @abstractmethod
    async def deleteInactiveDevices(self, bare_jid: str) -> None:
        """
        Delete the dictionary of inactive devices stored in this instance for the given bare JID, if any. Do
        not raise if there is none.

        Args:
            bare_jid: The bare JID.
        """

    @abstractmethod
    async def loadTrust(self, bare_jid: str, device_id: int) -> Optional[Trust]:
        """
        Args:
            bare_jid: The bare JID.
            device_id: The device id.

        Returns:
            The trust information stored in this instance for the given bare JID + device id, if any.
        """

    @abstractmethod
    async def deleteTrust(self, bare_jid: str, device_id: int) -> None:
        """
        Delete the trust information stored in this instance for the given bare JID + device id, if any. Do
        not raise if there is none.

        Args:
            bare_jid: The bare JID.
            device_id: The device id.
        """

    @abstractmethod
    async def listJIDs(self) -> Optional[List[str]]:
        """
        Returns:
            A list of all bare JIDs that have associated device lists stored in the storage, if any. For a
            bare JID to be included in the list, it doesn't matter if the associated device lists are empty or
            not. Return ``None`` if the list of bare JIDs has been deleted, do not return an empty list in
            that case.
        """

    @abstractmethod
    async def deleteJIDList(self) -> None:
        """
        Delete the list of bare JIDs as returned by :meth:`listJIDs`, if it exists. Do not raise if it
        doesn't.
        """


async def migrate(
    legacy_storage: LegacyStorage,
    storage: omemo.Storage,
    trusted_trust_level_name: str,
    undecided_trust_level_name: str,
    untrusted_trust_level_name: str,
    download_bundle: Callable[[str, int], Awaitable[BundleImpl]]
) -> None:
    """
    Migrate the data from a legacy storage instance to the current storage format. This function is
    idempotent, which means that you can run it without checking whether migrations are required or not. If
    migrations are not required, the function will do nothing. This function also makes sure that only safely
    migrated data is deleted from the legacy storage, such that migration failure at any point leaves both
    storages in a consistent state.

    Args:
        legacy_storage: The legacy storage instance to migrate the data from. This assumes that the storage
            was used with legacy (pre-1.0.0) python-omemo in conjunction with python-omemo-backend-signal. If
            the storage was used with a backend other than python-omemo-backend-signal, automated migration is
            not possible with this function.
        storage: The storage implementation to migrate the data to.
        trusted_trust_level_name: The legacy storage format stored trust as a boolean, i.e. there were only
            trusted or untrusted devices. This is the name of the custom trust level to store when a trusted
            device is migrated.
        undecided_trust_level_name: The name of the custom trust level to store when a device without any
            associated trust information is migrated.
        untrusted_trust_level_name: The name of the custom trust level to store when an untrusted device is
            migrated.
        download_bundle: A function which downloads the bundle of the given bare JID + device id. May raise
            :class:`~omemo.session_manager.BundleDownloadFailed` (or a subclass thereof) to indicate failure.
    """

    # python-omemo SessionManager
    # - f"/devices/{bare_jid}/{device_id}/namespaces" List[str]
    # - f"/devices/{bare_jid}/{device_id}/active" Dict[str, bool]
    # - f"/devices/{bare_jid}/{device_id}/label" Optional[str]
    # - f"/devices/{bare_jid}/{device_id}/identity_key" bytes
    # - f"/devices/{bare_jid}/list" List[int]
    # - f"/trust/{bare_jid}/{base64.urlsafe_b64encode(identity_key).decode('ASCII')}" str
    # - "/own_device_id" int

    # python-omemo IdentityKeyPair
    # - "/ikp/is_seed" bool
    # - "/ikp/key" 32 bytes

    # python-oldmemo
    # - f"/{self.namespace}/x3dh" x3dh.JSONObject
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/initiation" str
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/identity_key" bytes
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/ephemeral_key" bytes
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/signed_pre_key" bytes
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/signed_pre_key_id" int
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key" bytes
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/key_exchange/pre_key_id" int
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/associated_data" bytes
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/double_ratchet" doubleratchet.JSONObject
    # - f"/{self.namespace}/{session.bare_jid}/{session.device_id}/confirmed" bool
    # - f"/{self.namespace}/bare_jids" List[str]
    # - f"/{self.namespace}/{session.bare_jid}/device_ids" List[int]
    # - f"/{self.namespace}/signed_pre_key_ids" Dict[str, int]
    # - f"/{self.namespace}/pre_key_ids" Dict[str, int]
    # - f"/{self.namespace}/pre_key_id_counter" int

    # The own data is the very first thing to be loaded and the very last thing to be deleted.
    own_data = await legacy_storage.loadOwnData()
    if own_data is None:
        return

    # The own bare JID isn't part of the new storage format.
    await storage.store("/own_device_id", own_data["own_device_id"])

    # The legacy state format contains both the X3DH state and information required for the migration of
    # sessions
    state = await legacy_storage.loadState()
    if state is None:
        return

    # Migrate the X3DH state
    await storage.store(f"/{NAMESPACE}/x3dh", state["super"]["super"])

    # Now, load and migrate the own identity key since it's needed for session migrations later on. The own
    # identity key is part of the X3DH state. Parse the X3DH state and extract the identity key.
    base_state_model, _ = x3dh.migrations.parse_base_state_model(state["super"]["super"])

    # The base state model contains the secret and the secret type of the identity key
    own_identity_key_secret = base_state_model.identity_key.secret
    own_identity_key_secret_type = base_state_model.identity_key.secret_type

    # Migrate the secret
    await storage.store_bytes("/ikp/key", own_identity_key_secret)

    # The type of secret should be x3dh.types.SecretType.PRIV, since that's the only format supported by
    # legacy python-omemo + python-omemo-backend-signal, but it doesn't hurt to check the type anyway.
    await storage.store("/ikp/is_seed", own_identity_key_secret_type is x3dh.types.SecretType.SEED)

    # From the secret, we can calculate the Ed25519 public key
    own_identity_key = (
        xeddsa.seed_to_ed25519_pub(own_identity_key_secret)
        if own_identity_key_secret_type is x3dh.types.SecretType.SEED
        else xeddsa.priv_to_ed25519_pub(own_identity_key_secret)
    )

    # Prepare the identity key in the serialized format required to build the associated data later as part of
    # session migration
    own_identity_key_serialized = StateImpl.serialize_public_key(xeddsa.ed25519_pub_to_curve25519_pub(
        own_identity_key
    ))

    # With the state loaded and identity key prepared, begin with the migration of information related to
    # other devices, i.e. device information including trust and sessions.
    bare_jids = await legacy_storage.listJIDs()
    if bare_jids is not None:
        for bare_jid in bare_jids:
            # Load active and inactive devices of this bare JID
            active_devices = await legacy_storage.loadActiveDevices(bare_jid)
            inactive_devices = await legacy_storage.loadInactiveDevices(bare_jid)

            # The timestamp on the inactive devices is not needed
            active_device_ids = set() if active_devices is None else set(active_devices)
            inactive_device_ids = set() if inactive_devices is None else set(inactive_devices.keys())

            # Migrate general device information
            migrated_devices: Set[int] = set()
            for device_id in active_device_ids | inactive_device_ids:
                active = device_id in active_device_ids

                # At this point, there are two options: either, trust information for the device exists,
                # including the identity key of the device in Curve25519 format, or it doesn't. Either way,
                # there is a problem. The new format expects the identity key in Ed25519 format. To convert a
                # Curve25519 key to Ed25519, the missing sign bit has to be provided. The sign bit can be
                # fetched from the signed pre key signature included in the public bundle of the device. That
                # means, if the trust information including the Curve25519 identity is present, the bundle has
                # to be fetched for the sign bit. If the trust information is not present, the bundle has to
                # be fetched for the whole identity key. That means, either way, we need the bundle here.
                # The single exception is the own device, since out own identity key is available.
                identity_key: bytes

                if bare_jid == own_data["own_bare_jid"] and device_id == own_data["own_device_id"]:
                    identity_key = own_identity_key
                else:
                    try:
                        bundle = await download_bundle(bare_jid, device_id)
                    except omemo.BundleDownloadFailed:
                        # A device whose bundle can't be fetched cannot be migrated. Delete all data related
                        # to the device and skip to the next one.
                        await legacy_storage.deleteSession(bare_jid, device_id)
                        await legacy_storage.deleteTrust(bare_jid, device_id)
                        continue

                    # The BundleImpl structure contains the identity in Ed25519 form, thus no further
                    # conversion is required. The bundle parsing code has already taken care of extracting the
                    # sign bit from the signed pre key signature and converting the key from Curve25519
                    # format.
                    identity_key = bundle.identity_key

                # Load the trust information stored for this device.
                trust = await legacy_storage.loadTrust(bare_jid, device_id)

                # If trust information is available, verify that the identity key stored for the device
                # matches the one just fetched from the bundle
                if trust is not None:
                    legacy_storage_identity_key = base64.b64decode(trust["key"])

                    if xeddsa.ed25519_pub_to_curve25519_pub(identity_key) != legacy_storage_identity_key:
                        # If the stored identity key doesn't match the bundle identity key, the device is not
                        # migrated. Delete all data related to the device and skip to the next one.
                        await legacy_storage.deleteSession(bare_jid, device_id)
                        await legacy_storage.deleteTrust(bare_jid, device_id)
                        continue

                # Select the custom trust level name to assign to the device upon migration
                trust_level_name = undecided_trust_level_name
                if trust is not None:
                    if trust["trusted"]:
                        trust_level_name = trusted_trust_level_name
                    else:
                        trust_level_name = untrusted_trust_level_name

                # All available data about this device has been gathered, migrate it
                await storage.store(f"/devices/{bare_jid}/{device_id}/namespaces", [ NAMESPACE ])
                await storage.store(f"/devices/{bare_jid}/{device_id}/active", { NAMESPACE: active })
                await storage.store(f"/devices/{bare_jid}/{device_id}/label", None)
                await storage.store_bytes(f"/devices/{bare_jid}/{device_id}/identity_key", identity_key)
                await storage.store(
                    f"/trust/{bare_jid}/{base64.urlsafe_b64encode(identity_key).decode('ASCII')}",
                    trust_level_name
                )

                # The device has been migrated successfully, add it to the corresponding set but don't delete
                # its data yet.
                migrated_devices.add(device_id)

            # Write the list of successfully migrated devices
            await storage.store(f"/devices/{bare_jid}/list", list(migrated_devices))

            # Look for sessions with the successfully migrated devices and migrate those too
            migrated_sessions: Set[int] = set()
            for device_id in migrated_devices:
                session = await legacy_storage.loadSession(bare_jid, device_id)
                if session is None:
                    continue

                legacy_storage_identity_key = base64.b64decode(session["other_ik"])
                double_ratchet = session["super"]

                # Same situation as above: the identity key is only included in Curve25519 format, but is
                # needed in Ed25519 format to become part of the key exchange information. Luckily, we have
                # already requested the bundle above and stored the identity key in Ed25519 format. Load it
                # here (from cache) and make sure it matches the identity key stored in legacy storage.
                identity_key = (await storage.load_bytes(
                    f"/devices/{bare_jid}/{device_id}/identity_key"
                )).from_just()

                if xeddsa.ed25519_pub_to_curve25519_pub(identity_key) != legacy_storage_identity_key:
                    # If the stored identity key doesn't match the bundle identity key, the session is not
                    # migrated. Delete all data related to it and skip to the next one.
                    await legacy_storage.deleteSession(bare_jid, device_id)
                    continue

                # If the identity keys match, store the Ed25519 one.
                await storage.store_bytes(
                    f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/identity_key",
                    identity_key
                )

                # Prepare the serialized identity as needed to build the associated data byte string
                identity_key_serialized = StateImpl.serialize_public_key(
                    xeddsa.ed25519_pub_to_curve25519_pub(identity_key)
                )

                # A bunch of information stored in the new storage format wasn't directly available in the
                # legacy format, namely which party initiated the session, whether the session was confirmed
                # via the passive party responding, and the key exchange information that was used to build
                # the session. All of this information is used for protocol stability reasons regarding the
                # initial X3DH key agreement. Some of this information can be extracted/guessed from
                # "bound pre keys" that were used by the legacy format and stored with the state. Bound pre
                # keys are pre keys associated with passively initiated sessions upon creation, and deleted at
                # a user-defined point in the future, hopefully as soon as the session has been fully
                # confirmed and no more key exchange messages are to be expected. All implementations I know
                # of didn't delete bound pre keys at all, which is good for the migration. The presence of a
                # bound pre key indicates that a session was passively initiated and allows us to restore at
                # least part of the key exchange information. Sessions without an associated bound pre key are
                # migrated as actively initiated and confirmed, which is the constellation of parameters that
                # makes sure the missing key exchange information is never accessed.
                bound_otpk = state["bound_otpks"].get(bare_jid, {}).get(device_id)
                if bound_otpk is None:
                    # Set the initiation to active as explained above.
                    await storage.store(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/initiation",
                        Initiation.ACTIVE.name
                    )

                    # Store the associated data in the format expected for actively initated sessions.
                    await storage.store_bytes(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/associated_data",
                        own_identity_key_serialized + identity_key_serialized
                    )

                    # Without a bound pre key, the pre key and pre key id fields of the key exchange can't be
                    # set correctly. The KeyExchangeImpl class detects and handles the following filler values
                    # though:
                    await storage.store(f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/pre_key_id", -1)
                    await storage.store_bytes(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/pre_key",
                        b"\x00" * 32
                    )
                else:
                    # Set the initiation to passive as explained above.
                    await storage.store(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/initiation",
                        Initiation.PASSIVE.name
                    )

                    # Store the associated data in the format expected for passively initated sessions.
                    await storage.store_bytes(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/associated_data",
                        identity_key_serialized + own_identity_key_serialized
                    )

                    # With a bound pre key, we can at least fill the pre key and pre key id fields of the key
                    # exchange information correctly.
                    await storage.store(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/pre_key_id",
                        bound_otpk["id"]
                    )
                    await storage.store_bytes(
                        f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/pre_key",
                        base64.b64decode(bound_otpk["otpk"])
                    )

                # All sessions are marked as confirmed. This makes sure that the code never attempts to send
                # the incomplete key exchange information.
                await storage.store(f"/{NAMESPACE}/{bare_jid}/{device_id}/confirmed", True)

                # The serialized double ratchet just has to be assigned to the correct key.
                await storage.store(f"/{NAMESPACE}/{bare_jid}/{device_id}/double_ratchet", double_ratchet)

                # The ephemeral key, signed pre key and signed pre key ids used during key exchange are
                # unknown. The values in storage still have to be filled though. The KeyExchangeImpl class
                # detects and handles the following filler values correctly:
                await storage.store_bytes(
                    f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/ephemeral_key",
                    b"\x00" * 32
                )

                await storage.store(f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/signed_pre_key_id", -1)
                await storage.store_bytes(
                    f"/{NAMESPACE}/{bare_jid}/{device_id}/key_exchange/signed_pre_key",
                    b"\x00" * 32
                )

                # The session was migrated successfully, add it to the corresponding set but don't delete its
                # data yet.
                migrated_sessions.add(device_id)

            # Write the list of successfully migrated sessions
            await storage.store(f"/{NAMESPACE}/{bare_jid}/device_ids", list(migrated_sessions))

            # Migration completed for this bare JID, delete all legacy data to avoid double migration
            await legacy_storage.deleteActiveDevices(bare_jid)
            await legacy_storage.deleteInactiveDevices(bare_jid)
            for device_id in migrated_devices:
                await legacy_storage.deleteTrust(bare_jid, device_id)
            for device_id in migrated_sessions:
                await legacy_storage.deleteSession(bare_jid, device_id)

        # All bare JIDs have been migrated, write the list of bare JIDs...
        await storage.store(f"/{NAMESPACE}/bare_jids", list(bare_jids))

        # ...and delete the list of JIDs
        await legacy_storage.deleteJIDList()

    # What remains to be migrated are (signed) pre key id mappings and counters.

    # The legacy format didn't keep the old signed pre key around, so there is at most the current signed pre
    # key id to migrate, which is optional in the legacy storage format too.
    if state["super"]["spk_pub"] is not None:
        await storage.store(
            f"/{NAMESPACE}/signed_pre_key_ids",
            { state["super"]["spk_pub"]: state["super"]["spk_id"] }
        )

    # The pre key id mapping and id counter are already in the format/types required by the new storage
    # format, thus it's simply a matter of migrating them to their new keys.
    await storage.store(f"/{NAMESPACE}/pre_key_ids", state["super"]["otpk_ids"])
    await storage.store(f"/{NAMESPACE}/pre_key_id_counter", state["super"]["otpk_id_counter"])

    # Finally delete the legacy state and the own data.
    await legacy_storage.deleteState()
    await legacy_storage.deleteOwnData()
