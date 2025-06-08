import logging
import os
import struct
from datetime import datetime
from typing import Optional, List
from typing_extensions import Buffer

from tortoise import Tortoise, transactions
from tortoise.exceptions import DoesNotExist

from .config import get_tortoise_config
from .models.device import DeviceModel
from ...store.store import Device
from ...util.keys.keypair import KeyPair, PreKey

logger = logging.getLogger(__name__)

class Container:
    """Database container managing WhatsApp store operations"""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize Tortoise ORM connection"""
        if self._initialized:
            return

        config = get_tortoise_config(self.db_url)
        await Tortoise.init(config)
        await Tortoise.generate_schemas()
        self._initialized = True
        logger.info("Database initialized successfully")

    async def close(self) -> None:
        """Close database connections"""
        if self._initialized:
            await Tortoise.close_connections()
            self._initialized = False
            logger.info("Database connections closed")

    async def get_all_devices(self) -> List[Device]:
        """Get all registered devices"""
        devices = await DeviceModel.all()
        return [self._device_to_store(device) for device in devices]

    async def get_first_device(self) -> Optional[Device]:
        """Get the first available device, create one if none exist"""
        try:
            device = await DeviceModel.first()
            return self._device_to_store(device) if device else await self.new_device("new_device@temp.com")
        except DoesNotExist:
            # Create a new device if none exist (like Go implementation)
            return await self.new_device("new_device@temp.com")

    async def get_device(self, jid: str) -> Optional[Device]:
        """Get device by JID"""
        try:
            device = await DeviceModel.get(id=jid)
            return self._device_to_store(device)
        except DoesNotExist:
            return None

    async def new_device(self, jid: str) -> Device:
        """Create a new device with proper default values"""
        # Generate noise key
        noise_key = KeyPair.generate()

        # Generate identity key pair
        identity_key = KeyPair.generate()

        # Generate signed pre-key using the identity key (like Go does)
        signed_pre_key = identity_key.create_signed_pre_key(1)

        # Generate registration ID (random 32-bit integer)
        the_random_bytes: bytes
        the_random_bytes = os.urandom(4)
        the_random_bytes: 'Buffer'
        registration_id = struct.unpack(">I", the_random_bytes)[0]

        device = await DeviceModel.create(
            id=jid,
            registration_id=registration_id,
            noise_key_private=noise_key.priv,
            noise_key_public=noise_key.pub,
            signed_pre_key=signed_pre_key.pub,
            signed_pre_key_id=signed_pre_key.key_id,
            signed_pre_key_signature=signed_pre_key.signature,
            identity_key_private=identity_key.priv,
            identity_key_public=identity_key.pub,
            platform="android"
        )

        store = self._device_to_store(device)
        # Set the keys in the store
        store.noise_key = noise_key
        store.identity_key = identity_key
        store.signed_pre_key = signed_pre_key

        return store

    async def put_device(self, store: Device) -> None:
        """Save device to database"""
        await DeviceModel.update_or_create(
            id=store.id,
            defaults=self._store_to_device_dict(store)
        )

    async def delete_device(self, jid: str) -> None:
        """Delete device and all associated data"""
        async with transactions.in_transaction():
            # Delete device and cascade to related tables
            await DeviceModel.filter(id=jid).delete()
            # Additional cleanup for related tables
            from .models.session import IdentityKey, Session, PreKeyModel, SenderKey
            from .models.contacts import Contact
            from .models.appstate import AppStateSyncKey, AppStateVersion

            await IdentityKey.filter(our_jid=jid).delete()
            await Session.filter(our_jid=jid).delete()
            await PreKeyModel.filter(jid=jid).delete()
            await SenderKey.filter(our_jid=jid).delete()
            await Contact.filter(our_jid=jid).delete()
            await AppStateSyncKey.filter(jid=jid).delete()
            await AppStateVersion.filter(jid=jid).delete()

    def _device_to_store(self, device: DeviceModel) -> Device:
        """Convert Device model to DeviceStore"""
        store = Device()
        store.jid = device.id
        store.registration_id = device.registration_id

        # Reconstruct noise key from stored data
        if device.noise_key_private:
            store.noise_key = KeyPair(priv=device.noise_key_private, pub=device.noise_key_public)

        # Reconstruct identity key from stored data
        if device.identity_key_private:
            store.identity_key = KeyPair(priv=device.identity_key_private, pub=device.identity_key_public)

        # Reconstruct signed pre-key using PreKey (matches Go's keys.PreKey)
        if device.signed_pre_key and device.signed_pre_key_id and device.signed_pre_key_signature:
            # Create a KeyPair from the stored public key bytes
            # Note: We need the private key to create a proper KeyPair
            # For now, we'll create a PreKey with just the public key info
            key_pair = KeyPair(pub=device.signed_pre_key, priv=b'')  # Empty private key for now
            store.signed_pre_key = PreKey(
                key_pair=key_pair,
                key_id=device.signed_pre_key_id,
                signature=device.signed_pre_key_signature
            )

        # Only set fields that exist in the Go version
        store.platform = device.platform
        store.business_name = device.business_name
        store.push_name = device.push_name

        return store

    def _store_to_device_dict(self, store: Device) -> dict:
        """Convert DeviceStore to Device model dict"""
        data = {
            "registration_id": store.registration_id,
            "platform": store.platform or "android",
            "business_name": store.business_name,
            "push_name": store.push_name,
        }

        # Add noise key if available
        if store.noise_key:
            data.update({
                "noise_key_private": store.noise_key.priv,
                "noise_key_public": store.noise_key.pub,
            })

        # Add identity key if available
        if store.identity_key:
            data.update({
                "identity_key_private": store.identity_key.priv,
                "identity_key_public": store.identity_key.pub,
            })

        # Add signed pre-key if available
        if store.signed_pre_key:
            data.update({
                "signed_pre_key": store.signed_pre_key.pub,
                "signed_pre_key_id": store.signed_pre_key.key_id,
                "signed_pre_key_signature": store.signed_pre_key.signature,
            })

        return data
