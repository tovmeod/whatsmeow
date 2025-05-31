"""
Signal protocol store implementation for WhatsApp.

Port of whatsmeow/store/signal.go
"""
from typing import Optional, List, Any
import logging

# Signal protocol imports
from signal_protocol import curve, identity_key, state, storage, protocol, sender_keys, address
from signal_protocol.state import PreKeyRecord, SessionRecord, SignedPreKeyRecord
from signal_protocol.sender_keys import SenderKeyRecord, SenderKeyName

# Equivalent to Go's SignalProtobufSerializer = serialize.NewProtoBufSerializer()
# In Python, serialization is handled internally by the record classes
SignalProtobufSerializer = None

logger = logging.getLogger(__name__)

class SignalProtocolMixin:
    """
    Mixin class that adds Signal Protocol store methods to the Device class.

    This is equivalent to the methods added in store/signal.go in the Go implementation.
    """

    # IdentityKeyStore implementation
    async def get_identity_key_pair(self, ctx: Any = None) -> identity_key.IdentityKeyPair:
        """
        Get the identity key pair for this device.

        Go equivalent: func (device *Device) GetIdentityKeyPair() *identity.KeyPair
        """
        public_key = curve.PublicKey(self.identity_key.pub)
        private_key = curve.PrivateKey(self.identity_key.priv)
        return identity_key.IdentityKeyPair(
            identity_key.IdentityKey(public_key),
            private_key
        )

    async def get_local_registration_id(self, ctx: Any = None) -> int:
        """
        Get the registration ID for this device.

        Go equivalent: func (device *Device) GetLocalRegistrationID() uint32
        """
        return self.registration_id

    async def save_identity(self, ctx: Any, addr: address.ProtocolAddress, identity_key_obj: identity_key.IdentityKey) -> None:
        """
        Save an identity key for a remote address.

        Go equivalent: func (device *Device) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) error
        """
        addr_string = f"{addr.name}:{addr.device_id}"
        try:
            await self.identities.put_identity(ctx, addr_string, identity_key_obj.public_key.serialize())
        except Exception as e:
            logger.error(f"Failed to save identity of {addr_string}: {e}")
            raise Exception(f"failed to save identity of {addr_string}: {e}")

    async def is_trusted_identity(self, ctx: Any, addr: address.ProtocolAddress, identity_key_obj: identity_key.IdentityKey) -> bool:
        """
        Check if an identity key is trusted for a remote address.

        Go equivalent: func (device *Device) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) (bool, error)
        """
        addr_string = f"{addr.name}:{addr.device_id}"
        try:
            is_trusted = await self.identities.is_trusted_identity(ctx, addr_string, identity_key_obj.public_key.serialize())
            return is_trusted
        except Exception as e:
            logger.error(f"Failed to check if {addr_string}'s identity is trusted: {e}")
            raise Exception(f"failed to check if {addr_string}'s identity is trusted: {e}")

    # PreKeyStore implementation
    async def load_pre_key(self, ctx: Any, pre_key_id: int) -> Optional[PreKeyRecord]:
        """
        Load a pre-key by ID.

        Go equivalent: func (device *Device) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error)
        """
        try:
            pre_key = await self.pre_keys.get_pre_key(ctx, pre_key_id)
            if pre_key is None:
                return None

            # Create a new pre-key record with the key pair
            # In Go: record.NewPreKey(preKey.KeyID, ecc.NewECKeyPair(...), nil)
            public_key = curve.PublicKey(pre_key.pub)
            private_key = curve.PrivateKey(pre_key.priv)
            key_pair = curve.KeyPair(public_key, private_key)

            return PreKeyRecord.new(pre_key.key_id, key_pair)
        except Exception as e:
            logger.error(f"Failed to load pre-key {pre_key_id}: {e}")
            raise Exception(f"failed to load prekey {pre_key_id}: {e}")

    async def remove_pre_key(self, ctx: Any, pre_key_id: int) -> None:
        """
        Remove a pre-key.

        Go equivalent: func (device *Device) RemovePreKey(ctx context.Context, id uint32) error
        """
        try:
            await self.pre_keys.remove_pre_key(ctx, pre_key_id)
        except Exception as e:
            logger.error(f"Failed to remove pre-key {pre_key_id}: {e}")
            raise Exception(f"failed to remove prekey {pre_key_id}: {e}")

    async def store_pre_key(self, ctx: Any, pre_key_id: int, pre_key_record: PreKeyRecord) -> None:
        """
        Store a pre-key.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("store_pre_key is not implemented")

    async def contains_pre_key(self, ctx: Any, pre_key_id: int) -> bool:
        """
        Check if a pre-key exists.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("contains_pre_key is not implemented")

    # SessionStore implementation
    async def load_session(self, ctx: Any, addr: address.ProtocolAddress) -> SessionRecord:
        """
        Load a session for a remote address.

        Go equivalent: func (device *Device) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error)
        """
        addr_string = f"{addr.name}:{addr.device_id}"
        try:
            raw_sess = await self.sessions.get_session(ctx, addr_string)
            if raw_sess is None:
                # Create a new empty session record
                # In Go: record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
                return SessionRecord.new()

            try:
                # Deserialize the existing session record from bytes
                # In Go: record.NewSessionFromBytes(rawSess, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
                return SessionRecord.deserialize(raw_sess)
            except Exception as e:
                logger.error(f"Failed to deserialize session with {addr_string}: {e}")
                raise Exception(f"failed to deserialize session with {addr_string}: {e}")
        except Exception as e:
            logger.error(f"Failed to load session with {addr_string}: {e}")
            raise Exception(f"failed to load session with {addr_string}: {e}")

    async def get_sub_device_sessions(self, ctx: Any, name: str) -> list[int]:
        """
        Get all sub-device sessions for a name.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("get_sub_device_sessions is not implemented")

    async def store_session(self, ctx: Any, addr: address.ProtocolAddress, record: SessionRecord) -> None:
        """
        Store a session for a remote address.

        Go equivalent: func (device *Device) StoreSession(ctx context.Context, address *protocol.SignalAddress, record *record.Session) error
        """
        addr_string = f"{addr.name}:{addr.device_id}"
        try:
            await self.sessions.put_session(ctx, addr_string, record.serialize())
        except Exception as e:
            logger.error(f"Failed to store session with {addr_string}: {e}")
            raise Exception(f"failed to store session with {addr_string}: {e}")

    async def contains_session(self, ctx: Any, remote_addr: address.ProtocolAddress) -> bool:
        """
        Check if a session exists for a remote address.

        Go equivalent: func (device *Device) ContainsSession(ctx context.Context, remoteAddress *protocol.SignalAddress) (bool, error)
        """
        addr_string = f"{remote_addr.name}:{remote_addr.device_id}"
        try:
            has_session = await self.sessions.has_session(ctx, addr_string)
            return has_session
        except Exception as e:
            logger.error(f"Failed to check if store has session for {addr_string}: {e}")
            raise Exception(f"failed to check if store has session for {addr_string}: {e}")

    async def delete_session(self, ctx: Any, remote_address: address.ProtocolAddress) -> None:
        """
        Delete a session for a remote address.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("delete_session is not implemented")

    async def delete_all_sessions(self, ctx: Any) -> None:
        """
        Delete all sessions.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("delete_all_sessions is not implemented")

    # SignedPreKeyStore implementation
    async def load_signed_pre_key(self, ctx: Any, signed_pre_key_id: int) -> Optional[SignedPreKeyRecord]:
        """
        Load a signed pre-key by ID.

        Go equivalent: func (device *Device) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*record.SignedPreKey, error)
        """
        # This doesn't need to be async since it accesses the device's signed_pre_key directly,
        # similar to how it's done in the Go implementation
        if signed_pre_key_id == self.signed_pre_key.key_id:
            # In Go: record.NewSignedPreKey(signedPreKeyID, 0, ecc.NewECKeyPair(...), *device.SignedPreKey.Signature, nil)
            public_key = curve.PublicKey(self.signed_pre_key.pub)
            private_key = curve.PrivateKey(self.signed_pre_key.priv)
            key_pair = curve.KeyPair(public_key, private_key)

            return SignedPreKeyRecord.new(
                signed_pre_key_id,
                0,  # timestamp, not used in whatsmeow
                key_pair,
                self.signed_pre_key.signature
            )
        return None

    async def load_signed_pre_keys(self, ctx: Any) -> list[SignedPreKeyRecord]:
        """
        Load all signed pre-keys.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("load_signed_pre_keys is not implemented")

    async def store_signed_pre_key(self, ctx: Any, signed_pre_key_id: int, record: SignedPreKeyRecord) -> None:
        """
        Store a signed pre-key.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("store_signed_pre_key is not implemented")

    async def contains_signed_pre_key(self, ctx: Any, signed_pre_key_id: int) -> bool:
        """
        Check if a signed pre-key exists.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("contains_signed_pre_key is not implemented")

    async def remove_signed_pre_key(self, ctx: Any, signed_pre_key_id: int) -> None:
        """
        Remove a signed pre-key.

        Go equivalent: panic("not implemented") - this is not implemented in Go either
        """
        raise NotImplementedError("remove_signed_pre_key is not implemented")

    # SenderKeyStore implementation
    async def store_sender_key(self, ctx: Any, sender_key_name: SenderKeyName, key_record: SenderKeyRecord) -> None:
        """
        Store a sender key.

        Go equivalent: func (device *Device) StoreSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error
        """
        group_id = sender_key_name.group_id
        sender = sender_key_name.sender
        sender_string = f"{sender.name}:{sender.device_id}"
        try:
            await self.sender_keys.put_sender_key(ctx, group_id, sender_string, key_record.serialize())
        except Exception as e:
            logger.error(f"Failed to store sender key from {sender_string} for {group_id}: {e}")
            raise Exception(f"failed to store sender key from {sender_string} for {group_id}: {e}")

    async def load_sender_key(self, ctx: Any, sender_key_name: SenderKeyName) -> SenderKeyRecord:
        """
        Load a sender key.

        Go equivalent: func (device *Device) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error)
        """
        group_id = sender_key_name.group_id
        sender = sender_key_name.sender
        sender_string = f"{sender.name}:{sender.device_id}"
        try:
            raw_key = await self.sender_keys.get_sender_key(ctx, group_id, sender_string)
            if raw_key is None:
                # Create a new empty sender key record
                # In Go: groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
                return SenderKeyRecord.new()

            try:
                # Deserialize the existing sender key record from bytes
                # In Go: groupRecord.NewSenderKeyFromBytes(rawKey, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
                return SenderKeyRecord.deserialize(raw_key)
            except Exception as e:
                logger.error(f"Failed to deserialize sender key from {sender_string} for {group_id}: {e}")
                raise Exception(f"failed to deserialize sender key from {sender_string} for {group_id}: {e}")
        except Exception as e:
            logger.error(f"Failed to load sender key from {sender_string} for {group_id}: {e}")
            raise Exception(f"failed to load sender key from {sender_string} for {group_id}: {e}")
