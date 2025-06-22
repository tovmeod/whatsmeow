# from signal_protocol.storage import InMemSignalProtocolStore
import asyncio
import concurrent.futures
from typing import Any, Coroutine, List, Optional, TypeVar

import signal_protocol
from signal_protocol import address, curve, state
from signal_protocol.sender_keys import SenderKeyName, SenderKeyRecord
from tortoise import fields
from tortoise.exceptions import DoesNotExist
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


T = TypeVar("T")


def run_async_in_sync_context(coro: Coroutine[Any, Any, T]) -> T:
    """
    Run an async coroutine in a sync context.

    This handles both cases:
    - When there's a running event loop (uses thread pool)
    - When there's no running event loop (uses asyncio.run)
    """
    try:
        # Check if there's a running event loop, if it is not running this raises RuntimeError
        asyncio.get_running_loop()

        # If we get here, we're in an async context, so use thread pool
        def run_in_new_thread() -> T:
            new_loop = asyncio.new_event_loop()
            try:
                return new_loop.run_until_complete(coro)
            finally:
                new_loop.close()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(run_in_new_thread)
            return future.result()

    except RuntimeError:
        # No running event loop, we can use asyncio.run directly
        return asyncio.run(coro)


class TortoiseSignalStore(signal_protocol.storage.InMemSignalProtocolStore):
    # class TortoiseSignalStore:
    """
    Tortoise ORM-backed Signal Protocol store implementation.

    This provides persistent storage for all Signal Protocol state using Tortoise ORM.
    Based on InMemSignalProtocolStore but with database persistence.
    """

    def __init__(self, identity_key_pair: signal_protocol.identity_key.IdentityKeyPair, registration_id: int):
        self.identity_key_pair = identity_key_pair
        self.registration_id = registration_id

    # IdentityKeyStore methods
    def get_identity_key_pair(self) -> signal_protocol.identity_key.IdentityKeyPair:
        """Get our own identity key pair."""
        return self.identity_key_pair

    def get_local_registration_id(self) -> int:
        """Get our registration ID."""
        return self.registration_id

    def save_identity(
        self, protocol_address: address.ProtocolAddress, identity_key: signal_protocol.identity_key.IdentityKey
    ) -> bool:
        """Save identity key for a contact."""

        async def _save() -> bool:
            existing = await SignalIdentityKeyModel.filter(
                name=protocol_address.name, device_id=protocol_address.device_id
            ).first()

            key_data = identity_key.serialize()

            if existing:
                key_changed = existing.identity_key != key_data
                existing.identity_key = key_data
                await existing.save()
                return key_changed
            else:
                await SignalIdentityKeyModel.create(
                    name=protocol_address.name, device_id=protocol_address.device_id, identity_key=key_data
                )
                return True

        return run_async_in_sync_context(_save())

    def get_identity(
        self, protocol_address: address.ProtocolAddress
    ) -> Optional[signal_protocol.identity_key.IdentityKey]:
        """Get stored identity key for a contact."""

        async def _get() -> Optional[signal_protocol.identity_key.IdentityKey]:
            stored = await SignalIdentityKeyModel.filter(
                name=protocol_address.name, device_id=protocol_address.device_id
            ).first()

            if stored:
                return signal_protocol.identity_key.IdentityKey(stored.identity_key)
            return None

        return run_async_in_sync_context(_get())

    # async def is_trusted_identity(self, protocol_address: address.ProtocolAddress,
    #                               identity_key: identity_key.IdentityKey, direction: int) -> bool:
    #     """Check if an identity key is trusted."""
    #     stored = await SignalIdentityKeyModel.filter(
    #         name=protocol_address.name,
    #         device_id=protocol_address.device_id
    #     ).first()
    #
    #     if not stored:
    #         return True  # First time seeing this identity
    #
    #     stored_key = identity_key.IdentityKey.deserialize(stored.identity_key)
    #     return stored_key.serialize() == identity_key.serialize()

    # SessionStore methods
    def load_session(self, protocol_address: address.ProtocolAddress) -> Optional[state.SessionRecord]:
        """Load session from database."""

        async def _load() -> Optional[state.SessionRecord]:
            session = await SignalSessionModel.filter(
                name=protocol_address.name, device_id=protocol_address.device_id
            ).first()

            if session:
                return state.SessionRecord.deserialize(session.session_data)
            return None

        return run_async_in_sync_context(_load())

    def store_session(self, protocol_address: address.ProtocolAddress, record: state.SessionRecord) -> None:
        """Store session to database."""

        async def _store() -> None:
            session_data = record.serialize()

            session, created = await SignalSessionModel.get_or_create(
                name=protocol_address.name,
                device_id=protocol_address.device_id,
                defaults={"session_data": session_data},
            )

            if not created:
                session.session_data = session_data
                await session.save()

        run_async_in_sync_context(_store())

    # async def contains_session(self, protocol_address: address.ProtocolAddress) -> bool:
    #     """Check if session exists."""
    #     return await SignalSessionModel.filter(
    #         name=protocol_address.name,
    #         device_id=protocol_address.device_id
    #     ).exists()
    #
    # async def delete_session(self, protocol_address: address.ProtocolAddress) -> None:
    #     """Delete session."""
    #     await SignalSessionModel.filter(
    #         name=protocol_address.name,
    #         device_id=protocol_address.device_id
    #     ).delete()
    #
    # async def delete_all_sessions(self, name: str) -> None:
    #     """Delete all sessions for a contact."""
    #     await SignalSessionModel.filter(name=name).delete()
    #
    # async def get_sub_device_sessions(self, name: str) -> List[int]:
    #     """Get device IDs for a contact (excluding device 1)."""
    #     sessions = await SignalSessionModel.filter(name=name, device_id__not=1).all()
    #     return [s.device_id for s in sessions]

    # PreKeyStore methods
    def load_pre_key(self, pre_key_id: int) -> Optional[state.PreKeyRecord]:
        """Load prekey from database."""

        async def _get() -> Optional[state.PreKeyRecord]:
            prekey = await SignalPreKeyModel.filter(key_id=pre_key_id).first()
            if prekey:
                return state.PreKeyRecord.deserialize(prekey.key_data)
            return None

        return run_async_in_sync_context(_get())

    def save_pre_key(self, pre_key_id: int, record: state.PreKeyRecord) -> None:
        """Store prekey to database."""
        run_async_in_sync_context(self.asave_pre_key(pre_key_id, record))

    async def asave_pre_key(self, pre_key_id: int, record: state.PreKeyRecord) -> None:
        key_data = record.serialize()
        await SignalPreKeyModel.create(key_id=pre_key_id, key_data=key_data)

    def remove_pre_key(self, pre_key_id: int) -> None:
        """Remove prekey."""

        async def _delete() -> None:
            await SignalPreKeyModel.filter(key_id=pre_key_id).delete()

        run_async_in_sync_context(_delete())

    # SignedPreKeyStore methods
    def get_signed_pre_key(self, signed_pre_key_id: int) -> state.SignedPreKeyRecord:
        """Load signed prekey from database."""

        async def _get() -> state.SignedPreKeyRecord:
            signed_prekey = await SignalSignedPreKeyModel.filter(key_id=int(signed_pre_key_id)).first()
            if signed_prekey:
                return state.SignedPreKeyRecord.deserialize(signed_prekey.key_data)
            raise Exception(f"SignedPreKey {signed_pre_key_id} not found")

        return run_async_in_sync_context(_get())

    def save_signed_pre_key(self, signed_pre_key_id: int, record: state.SignedPreKeyRecord) -> None:
        """Load all signed prekeys."""

        async def _save() -> None:
            key_data = record.serialize()
            await SignalSignedPreKeyModel.update_or_create(
                key_id=int(signed_pre_key_id), defaults={"key_data": key_data}
            )

        run_async_in_sync_context(_save())

    def store_sender_key(self, sender_key_name: SenderKeyName, record: SenderKeyRecord) -> None:
        """Store sender key."""

        async def _store() -> None:
            key_data = record.serialize()
            await SignalSenderKeyModel.update_or_create(
                group_id=sender_key_name.group_id(),
                sender_name=sender_key_name.sender_name(),
                sender_device_id=sender_key_name.sender_device_id(),
                defaults={"key_data": key_data},
            )

        run_async_in_sync_context(_store())

    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]:
        """Load sender key."""

        async def _load() -> Optional[SenderKeyRecord]:
            try:
                sender_key = await SignalSenderKeyModel.get(
                    group_id=sender_key_name.group_id(),
                    sender_name=sender_key_name.sender_name(),
                    sender_device_id=sender_key_name.sender_device_id(),
                )
                return SenderKeyRecord.deserialize(sender_key.key_data)
            except DoesNotExist:
                return None

        return run_async_in_sync_context(_load())

    async def contains_session(self, protocol_address: address.ProtocolAddress) -> bool:
        """Check if session exists."""
        return await SignalSessionModel.filter(
            name=protocol_address.name, device_id=protocol_address.device_id
        ).exists()


# Helper functions for key generation
def generate_identity_keys() -> signal_protocol.identity_key.IdentityKeyPair:
    """Generate identity key pair using the signal_protocol API."""
    key_pair = curve.generate_keypair()
    public_key_bytes, private_key_bytes = key_pair

    # Create PrivateKey object from bytes
    private_key = curve.PrivateKey.deserialize(private_key_bytes)

    return signal_protocol.identity_key.IdentityKeyPair(
        signal_protocol.identity_key.IdentityKey(public_key_bytes),  # IdentityKey expects bytes directly
        private_key,  # IdentityKeyPair expects PrivateKey object
    )


def generate_prekeys(start_id: int, count: int) -> List[state.PreKeyRecord]:
    """Generate multiple prekeys."""
    return state.generate_n_prekeys(start_id, count)


# Example usage
def setup_signal_store() -> TortoiseSignalStore:
    """Example of how to set up the signal store."""
    # Generate identity keys
    identity_keys = generate_identity_keys()
    registration_id = 12345  # Should be generated randomly

    # Create the store
    store = TortoiseSignalStore(identity_keys, registration_id)

    # Generate and store prekeys
    prekeys = generate_prekeys(1, 100)
    for prekey in prekeys:
        store.save_pre_key(prekey.id(), prekey)

    return store
