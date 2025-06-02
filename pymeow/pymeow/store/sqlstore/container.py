import logging
import os
import struct
from datetime import datetime
from typing import Optional, List
from tortoise import Tortoise, transactions
from tortoise.exceptions import DoesNotExist
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .config import get_tortoise_config
from .models.device import Device
from ...prekeys import SignedPreKeyData
from ...store import Device as DeviceStore
from ...util.keys.keypair import KeyPair

logger = logging.getLogger(__name__)

class Container:
    """Database container managing WhatsApp store operations"""

    def __init__(self, db_url: str, logger: Optional[logging.Logger] = None):
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

    async def get_all_devices(self) -> List[DeviceStore]:
        """Get all registered devices"""
        devices = await Device.all()
        return [self._device_to_store(device) for device in devices]

    async def get_first_device(self) -> Optional[DeviceStore]:
        """Get the first available device, create one if none exist"""
        try:
            device = await Device.first()
            return self._device_to_store(device) if device else await self.new_device("new_device@temp.com")
        except DoesNotExist:
            # Create a new device if none exist (like Go implementation)
            return await self.new_device("new_device@temp.com")

    async def get_device(self, jid: str) -> Optional[DeviceStore]:
        """Get device by JID"""
        try:
            device = await Device.get(id=jid)
            return self._device_to_store(device)
        except DoesNotExist:
            return None

    async def new_device(self, jid: str) -> DeviceStore:
        """Create a new device with proper default values"""
        # Generate noise key (this was missing!)
        noise_key = KeyPair.generate()

        # Generate identity key pair
        identity_key = KeyPair.generate()

        # Generate signed pre-key using the identity key (like Go does)
        signed_pre_key = identity_key.create_signed_pre_key(1)

        # Generate registration ID (random 32-bit integer)
        registration_id = struct.unpack(">I", os.urandom(4))[0]

        device = await Device.create(
            id=jid,
            registration_id=registration_id,
            noise_key_private=noise_key.priv,  # Add noise key fields!
            noise_key_public=noise_key.pub,
            signed_pre_key=signed_pre_key.pub,
            signed_pre_key_id=signed_pre_key.key_id,
            signed_pre_key_signature=signed_pre_key.signature,
            identity_key_private=identity_key.priv,
            identity_key_public=identity_key.pub,
            platform="android"
        )

        store = self._device_to_store(device)
        # Set the noise key in the store (this was the missing piece!)
        store.noise_key = noise_key
        store.identity_key = identity_key
        store.signed_pre_key_pair = signed_pre_key

        return store

    async def put_device(self, store: DeviceStore) -> None:
        """Save device to database"""
        await Device.update_or_create(
            id=store.jid,
            defaults=self._store_to_device_dict(store)
        )

    async def delete_device(self, jid: str) -> None:
        """Delete device and all associated data"""
        async with transactions.in_transaction():
            # Delete device and cascade to related tables
            await Device.filter(id=jid).delete()
            # Additional cleanup for related tables
            from .models.session import IdentityKey, Session, PreKey, SenderKey
            from .models.contacts import Contact
            from .models.appstate import AppStateSyncKey, AppStateVersion

            await IdentityKey.filter(our_jid=jid).delete()
            await Session.filter(our_jid=jid).delete()
            await PreKey.filter(jid=jid).delete()
            await SenderKey.filter(our_jid=jid).delete()
            await Contact.filter(our_jid=jid).delete()
            await AppStateSyncKey.filter(jid=jid).delete()
            await AppStateVersion.filter(jid=jid).delete()

    def _device_to_store(self, device: Device) -> DeviceStore:
        """Convert Device model to DeviceStore"""
        store = DeviceStore()
        store.jid = device.id
        store.registration_id = device.registration_id

        # Reconstruct noise key from stored data
        if device.noise_key_private:
            store.noise_key = KeyPair(priv=device.noise_key_private, pub=device.noise_key_public)

        # Reconstruct identity key from stored data
        if device.identity_key_private:
            store.identity_key = KeyPair(priv=device.identity_key_private, pub=device.identity_key_public)

        # Reconstruct signed pre-key properly using SignedPreKeyData
        if device.signed_pre_key and device.signed_pre_key_id and device.signed_pre_key_signature:
            store.signed_pre_key = SignedPreKeyData(
                key_id=device.signed_pre_key_id,
                public_key=device.signed_pre_key,
                private_key=b'',  # You might need to store this separately if needed
                signature=device.signed_pre_key_signature,
                timestamp=datetime.now()  # You might want to store the actual timestamp
            )

        store.phone_id = device.phone_id
        store.device_id = device.device_id
        store.platform = device.platform
        store.business_name = device.business_name
        store.push_name = device.push_name
        return store

    def _store_to_device_dict(self, store: DeviceStore) -> dict:
        """Convert DeviceStore to Device model dict"""
        return {
            "registration_id": store.registration_id,
            "signed_pre_key": store.signed_pre_key,
            "signed_pre_key_id": store.signed_pre_key_id,
            "signed_pre_key_signature": store.signed_pre_key_signature,
            "identity_key_private": store.identity_key_private,
            "identity_key_public": store.identity_key_public,
            "phone_id": store.phone_id,
            "device_id": store.device_id,
            "platform": store.platform or "android",
            "business_name": store.business_name,
            "push_name": store.push_name,
        }
