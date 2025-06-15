# from signal_protocol.storage import InMemSignalProtocolStore
from typing import List, Optional

from signal_protocol import address, curve, identity_key, state
from signal_protocol.storage import InMemSignalProtocolStore
from tortoise import fields
from tortoise.models import Model


# Tortoise ORM Models
class SignalSessionModel(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255)
    device_id = fields.IntField()
    session_data = fields.BinaryField()

    class Meta:
        table = "pymeow_signal_sessions"
        unique_together = (("name", "device_id"),)


class SignalPreKeyModel(Model):
    id = fields.IntField(pk=True)
    key_id = fields.IntField(unique=True)
    key_data = fields.BinaryField()

    class Meta:
        table = "pymeow_signal_prekeys"


class SignalSignedPreKeyModel(Model):
    id = fields.IntField(pk=True)
    key_id = fields.IntField(unique=True)
    key_data = fields.BinaryField()
    timestamp = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "pymeow_signal_signed_prekeys"


class SignalIdentityKeyModel(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255)
    device_id = fields.IntField()
    identity_key = fields.BinaryField()

    class Meta:
        table = "pymeow_signal_identity_keys"
        unique_together = (("name", "device_id"),)


class SignalSenderKeyModel(Model):
    id = fields.IntField(pk=True)
    group_id = fields.CharField(max_length=255)
    sender_name = fields.CharField(max_length=255)
    sender_device_id = fields.IntField()
    key_data = fields.BinaryField()

    class Meta:
        table = "pymeow_signal_sender_keys"
        unique_together = (("group_id", "sender_name", "sender_device_id"),)


class TortoiseSignalStore(InMemSignalProtocolStore):
    """
    Tortoise ORM-backed Signal Protocol store implementation.

    This provides persistent storage for all Signal Protocol state using Tortoise ORM.
    Based on InMemSignalProtocolStore but with database persistence.
    """

    def __init__(self, identity_key_pair: identity_key.IdentityKeyPair, registration_id: int):
        self.identity_key_pair = identity_key_pair
        self.registration_id = registration_id

    # IdentityKeyStore methods
    async def get_identity_key_pair(self) -> identity_key.IdentityKeyPair:
        """Get our own identity key pair."""
        return self.identity_key_pair

    async def get_local_registration_id(self) -> int:
        """Get our registration ID."""
        return self.registration_id

    async def save_identity(self, protocol_address: address.ProtocolAddress,
                            identity_key: identity_key.IdentityKey) -> bool:
        """Save identity key for a contact."""
        existing = await SignalIdentityKeyModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).first()

        key_data = identity_key.serialize()

        if existing:
            # Check if key changed
            key_changed = existing.identity_key != key_data
            existing.identity_key = key_data
            await existing.save()
            return key_changed
        else:
            await SignalIdentityKeyModel.create(
                name=protocol_address.name,
                device_id=protocol_address.device_id,
                identity_key=key_data
            )
            return True

    async def is_trusted_identity(self, protocol_address: address.ProtocolAddress,
                                  identity_key: identity_key.IdentityKey, direction: int) -> bool:
        """Check if an identity key is trusted."""
        stored = await SignalIdentityKeyModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).first()

        if not stored:
            return True  # First time seeing this identity

        stored_key = identity_key.IdentityKey.deserialize(stored.identity_key)
        return stored_key.serialize() == identity_key.serialize()

    async def get_identity(self, protocol_address: address.ProtocolAddress) -> Optional[identity_key.IdentityKey]:
        """Get stored identity key for a contact."""
        stored = await SignalIdentityKeyModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).first()

        if stored:
            return identity_key.IdentityKey.deserialize(stored.identity_key)
        return None

    # SessionStore methods
    async def load_session(self, protocol_address: address.ProtocolAddress) -> Optional[state.SessionRecord]:
        """Load session from database."""
        session = await SignalSessionModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).first()

        if session:
            return state.SessionRecord.deserialize(session.session_data)
        return None

    async def store_session(self, protocol_address: address.ProtocolAddress, record: state.SessionRecord) -> None:
        """Store session to database."""
        session_data = record.serialize()

        session, created = await SignalSessionModel.get_or_create(
            name=protocol_address.name,
            device_id=protocol_address.device_id,
            defaults={'session_data': session_data}
        )

        if not created:
            session.session_data = session_data
            await session.save()

    async def contains_session(self, protocol_address: address.ProtocolAddress) -> bool:
        """Check if session exists."""
        return await SignalSessionModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).exists()

    async def delete_session(self, protocol_address: address.ProtocolAddress) -> None:
        """Delete session."""
        await SignalSessionModel.filter(
            name=protocol_address.name,
            device_id=protocol_address.device_id
        ).delete()

    async def delete_all_sessions(self, name: str) -> None:
        """Delete all sessions for a contact."""
        await SignalSessionModel.filter(name=name).delete()

    async def get_sub_device_sessions(self, name: str) -> List[int]:
        """Get device IDs for a contact (excluding device 1)."""
        sessions = await SignalSessionModel.filter(name=name, device_id__not=1).all()
        return [s.device_id for s in sessions]

    # PreKeyStore methods
    async def load_pre_key(self, pre_key_id: int) -> Optional[state.PreKeyRecord]:
        """Load prekey from database."""
        prekey = await SignalPreKeyModel.filter(key_id=pre_key_id).first()
        if prekey:
            return state.PreKeyRecord.deserialize(prekey.key_data)
        return None

    async def store_pre_key(self, pre_key_id: int, record: state.PreKeyRecord) -> None:
        """Store prekey to database."""
        key_data = record.serialize()
        await SignalPreKeyModel.create(key_id=pre_key_id, key_data=key_data)

    async def contains_pre_key(self, pre_key_id: int) -> bool:
        """Check if prekey exists."""
        return await SignalPreKeyModel.filter(key_id=pre_key_id).exists()

    async def remove_pre_key(self, pre_key_id: int) -> None:
        """Remove prekey."""
        await SignalPreKeyModel.filter(key_id=pre_key_id).delete()

    # SignedPreKeyStore methods
    async def load_signed_pre_key(self, signed_pre_key_id: int) -> Optional[state.SignedPreKeyRecord]:
        """Load signed prekey from database."""
        signed_prekey = await SignalSignedPreKeyModel.filter(key_id=signed_pre_key_id).first()
        if signed_prekey:
            return state.SignedPreKeyRecord.deserialize(signed_prekey.key_data)
        return None

    async def load_signed_pre_keys(self) -> List[state.SignedPreKeyRecord]:
        """Load all signed prekeys."""
        signed_prekeys = await SignalSignedPreKeyModel.all()
        return [state.SignedPreKeyRecord.deserialize(spk.key_data) for spk in signed_prekeys]

    async def store_signed_pre_key(self, signed_pre_key_id: int, record: state.SignedPreKeyRecord) -> None:
        """Store signed prekey."""
        key_data = record.serialize()
        await SignalSignedPreKeyModel.create(key_id=signed_pre_key_id, key_data=key_data)

    async def contains_signed_pre_key(self, signed_pre_key_id: int) -> bool:
        """Check if signed prekey exists."""
        return await SignalSignedPreKeyModel.filter(key_id=signed_pre_key_id).exists()

    async def remove_signed_pre_key(self, signed_pre_key_id: int) -> None:
        """Remove signed prekey."""
        await SignalSignedPreKeyModel.filter(key_id=signed_pre_key_id).delete()


# Helper functions for key generation
def generate_identity_keys() -> identity_key.IdentityKeyPair:
    """Generate identity key pair using the signal_protocol API."""
    key_pair = curve.generate_keypair()
    return identity_key.IdentityKeyPair(
        identity_key.IdentityKey(key_pair[0]),  # public key
        key_pair[1]  # private key
    )


def generate_prekeys(start_id: int, count: int) -> List[state.PreKeyRecord]:
    """Generate multiple prekeys."""
    return state.generate_n_prekeys(start_id, count)


# Example usage
async def setup_signal_store():
    """Example of how to set up the signal store."""
    # Generate identity keys
    identity_keys = generate_identity_keys()
    registration_id = 12345  # Should be generated randomly

    # Create the store
    store = TortoiseSignalStore(identity_keys, registration_id)

    # Generate and store prekeys
    prekeys = generate_prekeys(1, 100)
    for prekey in prekeys:
        await store.store_pre_key(prekey.id, prekey)

    return store
