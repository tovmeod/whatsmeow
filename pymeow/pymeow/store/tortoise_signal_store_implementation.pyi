from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol import identity_key, address, state
from signal_protocol.sender_keys import SenderKeyName, SenderKeyRecord
from typing import Optional, List
from tortoise.models import Model
from tortoise import fields

# Export all the Tortoise ORM Models
class SignalSessionModel(Model):
    id: fields.IntField
    name: fields.CharField
    device_id: fields.IntField
    session_data: fields.BinaryField

class SignalPreKeyModel(Model):
    id: fields.IntField
    key_id: fields.IntField
    key_data: fields.BinaryField

class SignalSignedPreKeyModel(Model):
    id: fields.IntField
    key_id: fields.IntField
    key_data: fields.BinaryField
    timestamp: fields.DatetimeField

class SignalIdentityKeyModel(Model):
    id: fields.IntField
    name: fields.CharField
    device_id: fields.IntField
    identity_key: fields.BinaryField

class SignalSenderKeyModel(Model):
    id: fields.IntField
    group_id: fields.CharField
    sender_name: fields.CharField
    sender_device_id: fields.IntField
    key_data: fields.BinaryField

# Export helper functions
def generate_identity_keys() -> identity_key.IdentityKeyPair: ...
def generate_prekeys(start_id: int, count: int) -> List[state.PreKeyRecord]: ...
def setup_signal_store() -> TortoiseSignalStore: ...

class TortoiseSignalStore(InMemSignalProtocolStore):
    def __init__(self, identity_key_pair: identity_key.IdentityKeyPair, registration_id: int) -> None: ...

    # IdentityKeyStore methods
    def get_identity_key_pair(self) -> identity_key.IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...
    def save_identity(
        self, protocol_address: address.ProtocolAddress, identity_key: identity_key.IdentityKey
    ) -> bool: ...
    def get_identity(self, protocol_address: address.ProtocolAddress) -> Optional[identity_key.IdentityKey]: ...

    # SessionStore methods
    def load_session(self, protocol_address: address.ProtocolAddress) -> Optional[state.SessionRecord]: ...
    def store_session(self, protocol_address: address.ProtocolAddress, record: state.SessionRecord) -> None: ...
    async def contains_session(self, protocol_address: address.ProtocolAddress) -> bool: ...

    # PreKeyStore methods
    def load_pre_key(self, pre_key_id: int) -> Optional[state.PreKeyRecord]: ...
    def save_pre_key(self, pre_key_id: int, record: state.PreKeyRecord) -> None: ...
    def remove_pre_key(self, pre_key_id: int) -> None: ...

    # SignedPreKeyStore methods
    def get_signed_pre_key(self, signed_pre_key_id: int) -> state.SignedPreKeyRecord: ...
    def save_signed_pre_key(self, signed_pre_key_id: int, record: state.SignedPreKeyRecord) -> None: ...

    # SenderKeyStore methods
    def store_sender_key(self, sender_key_name: SenderKeyName, record: SenderKeyRecord) -> None: ...
    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]: ...

    # Async methods
    async def asave_pre_key(self, pre_key_id: int, record: state.PreKeyRecord) -> None: ...
