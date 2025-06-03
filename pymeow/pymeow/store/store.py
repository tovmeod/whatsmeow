"""
Store interfaces for WhatsApp data needed for multidevice functionality.

Port of whatsmeow/store/store.go
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Callable, Any, Protocol, TypeVar, ByteString
import uuid
import asyncio

# Protobuf imports
from ..generated.waAdv import WAAdv_pb2

# Internal imports
from ..types.jid import JID, EMPTY_JID
from ..util.keys.keypair import KeyPair, PreKey
import logging


class IdentityStore(ABC):
    """Interface for storing identity keys."""

    @abstractmethod
    async def put_identity(self, address: str, key: bytes) -> None:
        """Store an identity key for an address."""
        pass

    @abstractmethod
    async def delete_all_identities(self, phone: str) -> None:
        """Delete all identity keys for a phone number."""
        pass

    @abstractmethod
    async def delete_identity(self, address: str) -> None:
        """Delete an identity key for an address."""
        pass

    @abstractmethod
    async def is_trusted_identity(self, address: str, key: bytes) -> Tuple[bool, Optional[Exception]]:
        """Check if an identity key is trusted."""
        pass


class SessionStore(ABC):
    """Interface for storing session data."""

    @abstractmethod
    async def get_session(self, address: str) -> Tuple[Optional[bytes], Optional[Exception]]:
        """Get a session for an address."""
        pass

    @abstractmethod
    async def has_session(self, address: str) -> Tuple[bool, Optional[Exception]]:
        """Check if a session exists for an address."""
        pass

    @abstractmethod
    async def put_session(self, address: str, session: bytes) -> None:
        """Store a session for an address."""
        pass

    @abstractmethod
    async def delete_all_sessions(self, phone: str) -> None:
        """Delete all sessions for a phone number."""
        pass

    @abstractmethod
    async def delete_session(self, address: str) -> None:
        """Delete a session for an address."""
        pass

    @abstractmethod
    async def migrate_pn_to_lid(self, pn: JID, lid: JID) -> None:
        """Migrate a session from a phone number to a LID."""
        pass


class PreKeyStore(ABC):
    """Interface for storing pre-keys."""

    @abstractmethod
    async def get_or_gen_pre_keys(self, count: int) -> List[PreKey]:
        """Get or generate pre-keys."""
        pass

    @abstractmethod
    async def gen_one_pre_key(self) -> Tuple[Optional[PreKey], Optional[Exception]]:
        """Generate a single pre-key."""
        pass

    @abstractmethod
    async def get_pre_key(self, key_id: int) -> Tuple[Optional[PreKey], Optional[Exception]]:
        """Get a pre-key by ID."""
        pass

    @abstractmethod
    async def remove_pre_key(self, key_id: int) -> None:
        """Remove a pre-key by ID."""
        pass

    @abstractmethod
    async def mark_pre_keys_as_uploaded(self, up_to_id: int) -> None:
        """Mark pre-keys as uploaded up to a specific ID."""
        pass

    @abstractmethod
    async def uploaded_prekey_count(self, ctx: Any) -> int:
        """Get the count of uploaded pre-keys."""
        pass


class SenderKeyStore(ABC):
    """Interface for storing sender keys."""

    @abstractmethod
    async def put_sender_key(self, group: str, user: str, session: bytes) -> None:
        """Store a sender key for a group and user."""
        pass

    @abstractmethod
    async def get_sender_key(self, group: str, user: str) -> Tuple[Optional[bytes], Optional[Exception]]:
        """Get a sender key for a group and user."""
        pass


@dataclass
class AppStateSyncKey:
    """App state sync key data."""

    data: bytes = field(default_factory=bytes)
    fingerprint: bytes = field(default_factory=bytes)
    timestamp: int = 0


class AppStateSyncKeyStore(ABC):
    """Interface for storing app state sync keys."""

    @abstractmethod
    async def put_app_state_sync_key(self, id: bytes, key: AppStateSyncKey) -> None:
        """Store an app state sync key."""
        pass

    @abstractmethod
    async def get_app_state_sync_key(self, id: bytes) -> Tuple[Optional[AppStateSyncKey], Optional[Exception]]:
        """Get an app state sync key by ID."""
        pass

    @abstractmethod
    async def get_latest_app_state_sync_key_id(self) -> Tuple[Optional[bytes], Optional[Exception]]:
        """Get the latest app state sync key ID."""
        pass


@dataclass
class AppStateMutationMAC:
    """App state mutation MAC data."""

    index_mac: bytes = field(default_factory=bytes)
    value_mac: bytes = field(default_factory=bytes)


class AppStateStore(ABC):
    """Interface for storing app state data."""

    @abstractmethod
    async def put_app_state_version(self, name: str, version: int, hash: bytes) -> None:
        """Store an app state version."""
        pass

    @abstractmethod
    async def get_app_state_version(self, name: str) -> Tuple[int, bytes, Optional[Exception]]:
        """Get an app state version by name."""
        pass

    @abstractmethod
    async def delete_app_state_version(self, name: str) -> None:
        """Delete an app state version by name."""
        pass

    @abstractmethod
    async def put_app_state_mutation_macs(self, name: str, version: int, mutations: List[AppStateMutationMAC]) -> None:
        """Store app state mutation MACs."""
        pass

    @abstractmethod
    async def delete_app_state_mutation_macs(self, name: str, index_macs: List[bytes]) -> None:
        """Delete app state mutation MACs."""
        pass

    @abstractmethod
    async def get_app_state_mutation_mac(self, name: str, index_mac: bytes) -> Tuple[Optional[bytes], Optional[Exception]]:
        """Get an app state mutation MAC by name and index MAC."""
        pass


@dataclass
class ContactEntry:
    """Contact entry data."""

    jid: JID = field(default_factory=lambda: EMPTY_JID)
    first_name: str = ""
    full_name: str = ""


class ContactStore(ABC):
    """Interface for storing contact data."""

    @abstractmethod
    async def put_push_name(self, user: JID, push_name: str) -> Tuple[bool, str, Optional[Exception]]:
        """Store a push name for a user."""
        pass

    @abstractmethod
    async def put_business_name(self, user: JID, business_name: str) -> Tuple[bool, str, Optional[Exception]]:
        """Store a business name for a user."""
        pass

    @abstractmethod
    async def put_contact_name(self, user: JID, full_name: str, first_name: str) -> None:
        """Store a contact name for a user."""
        pass

    @abstractmethod
    async def put_all_contact_names(self, ctx: Any, contacts: List[ContactEntry]) -> None:
        """Store contact names for multiple users."""
        pass

    @abstractmethod
    async def get_contact(self, user: JID) -> Tuple[Any, Optional[Exception]]:
        """Get contact info for a user."""
        pass

    @abstractmethod
    async def get_all_contacts(self) -> Tuple[Dict[JID, Any], Optional[Exception]]:
        """Get contact info for all users."""
        pass


class ChatSettingsStore(ABC):
    """Interface for storing chat settings."""

    @abstractmethod
    async def put_muted_until(self, ctx: Any, chat: JID, muted_until: datetime) -> None:
        """Store the muted until time for a chat."""
        pass

    @abstractmethod
    async def put_pinned(self, ctx: Any, chat: JID, pinned: bool) -> None:
        """Store the pinned status for a chat."""
        pass

    @abstractmethod
    async def put_archived(self, ctx: Any, chat: JID, archived: bool) -> None:
        """Store the archived status for a chat."""
        pass

    @abstractmethod
    async def get_chat_settings(self, ctx: Any, chat: JID) -> Tuple[Any, Optional[Exception]]:
        """Get settings for a chat."""
        pass


class DeviceContainer(ABC):
    """Interface for storing devices."""

    @abstractmethod
    async def put_device(self, ctx: Any, device: 'Device') -> None:
        """Store a device."""
        pass

    @abstractmethod
    async def delete_device(self, ctx: Any, device: 'Device') -> None:
        """Delete a device."""
        pass


@dataclass
class MessageSecretInsert:
    """Message secret insert data."""

    chat: JID = field(default_factory=lambda: EMPTY_JID)
    sender: JID = field(default_factory=lambda: EMPTY_JID)
    id: str = ""
    secret: bytes = field(default_factory=bytes)


class MsgSecretStore(ABC):
    """Interface for storing message secrets."""

    @abstractmethod
    async def put_message_secrets(self, ctx: Any, inserts: List[MessageSecretInsert]) -> None:
        """Store multiple message secrets."""
        pass

    @abstractmethod
    async def put_message_secret(self, ctx: Any, chat: JID, sender: JID, id: str, secret: bytes) -> None:
        """Store a message secret."""
        pass

    @abstractmethod
    async def get_message_secret(self, ctx: Any, chat: JID, sender: JID, id: str) -> Tuple[Optional[bytes], Optional[Exception]]:
        """Get a message secret."""
        pass


@dataclass
class PrivacyToken:
    """Privacy token data."""

    user: JID = field(default_factory=lambda: EMPTY_JID)
    token: bytes = field(default_factory=bytes)
    timestamp: datetime = field(default_factory=datetime.now)


class PrivacyTokenStore(ABC):
    """Interface for storing privacy tokens."""

    @abstractmethod
    async def put_privacy_tokens(self, ctx: Any, tokens: List[PrivacyToken]) -> None:
        """Store multiple privacy tokens."""
        pass

    @abstractmethod
    async def get_privacy_token(self, ctx: Any, user: JID) -> Tuple[Optional[PrivacyToken], Optional[Exception]]:
        """Get a privacy token for a user."""
        pass


@dataclass
class BufferedEvent:
    """Buffered event data."""

    plaintext: bytes = field(default_factory=bytes)
    insert_time: datetime = field(default_factory=datetime.now)
    server_time: datetime = field(default_factory=datetime.now)


class EventBuffer(ABC):
    """Interface for buffering events."""

    @abstractmethod
    async def get_buffered_event(self, ctx: Any, ciphertext_hash: bytes) -> Tuple[Optional[BufferedEvent], Optional[Exception]]:
        """Get a buffered event by ciphertext hash."""
        pass

    @abstractmethod
    async def put_buffered_event(self, ctx: Any, ciphertext_hash: bytes, plaintext: bytes, server_timestamp: datetime) -> None:
        """Store a buffered event."""
        pass

    @abstractmethod
    async def do_decryption_txn(self, ctx: Any, fn: Callable[[Any], Any]) -> None:
        """Execute a function within a decryption transaction."""
        pass

    @abstractmethod
    async def clear_buffered_event_plaintext(self, ctx: Any, ciphertext_hash: bytes) -> None:
        """Clear the plaintext of a buffered event."""
        pass

    @abstractmethod
    async def delete_old_buffered_hashes(self, ctx: Any) -> None:
        """Delete old buffered event hashes."""
        pass


@dataclass
class LIDMapping:
    """LID mapping data."""

    lid: JID = field(default_factory=lambda: EMPTY_JID)
    pn: JID = field(default_factory=lambda: EMPTY_JID)


class LIDStore(ABC):
    """Interface for storing LID mappings."""

    @abstractmethod
    async def put_many_lid_mappings(self, ctx: Any, mappings: List[LIDMapping]) -> None:
        """Store multiple LID mappings."""
        pass

    @abstractmethod
    async def put_lid_mapping(self, ctx: Any, lid: JID, jid: JID) -> None:
        """Store a LID mapping."""
        pass

    @abstractmethod
    async def get_pn_for_lid(self, ctx: Any, lid: JID) -> Tuple[Optional[JID], Optional[Exception]]:
        """Get a phone number for a LID."""
        pass

    @abstractmethod
    async def get_lid_for_pn(self, ctx: Any, pn: JID) -> Tuple[Optional[JID], Optional[Exception]]:
        """Get a LID for a phone number."""
        pass


class AllSessionSpecificStores(IdentityStore, SessionStore, PreKeyStore, SenderKeyStore,
                              AppStateSyncKeyStore, AppStateStore, ContactStore,
                              ChatSettingsStore, MsgSecretStore, PrivacyTokenStore,
                              EventBuffer):
    """Interface combining all session-specific stores."""
    pass


class AllGlobalStores(LIDStore):
    """Interface combining all global stores."""
    pass


class AllStores(AllSessionSpecificStores, AllGlobalStores):
    """Interface combining all stores."""
    pass


@dataclass
class BaseDevice:
    """Device data and associated stores."""

    log: Optional[logging.Logger] = None

    noise_key: Optional[KeyPair] = None
    identity_key: Optional[KeyPair] = None
    signed_pre_key: Optional[PreKey] = None
    registration_id: int = 0
    adv_secret_key: bytes = field(default_factory=bytes)

    id: Optional[JID] = None
    lid: JID = field(default_factory=lambda: EMPTY_JID)
    account: Optional[WAAdv_pb2.ADVSignedDeviceIdentity] = None
    platform: str = ""
    business_name: str = ""
    push_name: str = ""

    facebook_uuid: uuid.UUID = field(default_factory=uuid.uuid4)

    initialized: bool = False
    identities: Optional[IdentityStore] = None
    sessions: Optional[SessionStore] = None
    pre_keys: Optional[PreKeyStore] = None
    sender_keys: Optional[SenderKeyStore] = None
    app_state_keys: Optional[AppStateSyncKeyStore] = None
    app_state: Optional[AppStateStore] = None
    contacts: Optional[ContactStore] = None
    chat_settings: Optional[ChatSettingsStore] = None
    msg_secrets: Optional[MsgSecretStore] = None
    privacy_tokens: Optional[PrivacyTokenStore] = None
    event_buffer: Optional[EventBuffer] = None
    lids: Optional[LIDStore] = None
    container: Optional[DeviceContainer] = None

    def get_jid(self) -> JID:
        """Get the JID of this device."""
        if self is None or self.id is None:
            return EMPTY_JID
        return self.id

    def get_lid(self) -> JID:
        """Get the LID of this device."""
        if self is None:
            return EMPTY_JID
        return self.lid

    async def save(self, ctx: Any) -> Optional[Exception]:
        """Save this device to its container."""
        if self.container:
            return await self.container.put_device(ctx, self)
        return None

    async def delete(self, ctx: Any) -> Optional[Exception]:
        """Delete this device from its container."""
        if self.container:
            err = await self.container.delete_device(ctx, self)
            if err:
                return err
            self.id = None
            self.lid = EMPTY_JID
        return None
