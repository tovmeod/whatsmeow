import logging
import os
import struct
from typing import Optional, List
from tortoise import Tortoise, transactions
from tortoise.exceptions import DoesNotExist
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .config import get_tortoise_config
from .models.device import Device
from ...store import Device as DeviceStore

class Container:
    """Database container managing WhatsApp store operations"""

    def __init__(self, db_url: str, logger: Optional[logging.Logger] = None):
        self.db_url = db_url
        self.log = logger or logging.getLogger(__name__)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize Tortoise ORM connection"""
        if self._initialized:
            return

        config = get_tortoise_config(self.db_url)
        await Tortoise.init(config)
        await Tortoise.generate_schemas()
        self._initialized = True
        self.log.info("Database initialized successfully")

    async def close(self) -> None:
        """Close database connections"""
        if self._initialized:
            await Tortoise.close_connections()
            self._initialized = False
            self.log.info("Database connections closed")

    async def get_all_devices(self) -> List[DeviceStore]:
        """Get all registered devices"""
        devices = await Device.all()
        return [self._device_to_store(device) for device in devices]

    async def get_first_device(self) -> Optional[DeviceStore]:
        """Get the first available device"""
        try:
            device = await Device.first()
            return self._device_to_store(device) if device else None
        except DoesNotExist:
            return None

    async def get_device(self, jid: str) -> Optional[DeviceStore]:
        """Get device by JID"""
        try:
            device = await Device.get(id=jid)
            return self._device_to_store(device)
        except DoesNotExist:
            return None

    async def new_device(self, jid: str) -> DeviceStore:
        """Create a new device with proper default values"""
        # Generate identity key pair
        identity_private_key = x25519.X25519PrivateKey.generate()
        identity_public_key = identity_private_key.public_key()

        # Generate signed pre-key
        signed_pre_key_private = x25519.X25519PrivateKey.generate()
        signed_pre_key_public = signed_pre_key_private.public_key()

        # For now, use a dummy signature (in real implementation, this would be signed by identity key)
        dummy_signature = os.urandom(64)

        # Generate registration ID (random 32-bit integer)
        registration_id = struct.unpack(">I", os.urandom(4))[0]

        device = await Device.create(
            id=jid,
            registration_id=registration_id,
            signed_pre_key=signed_pre_key_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            signed_pre_key_id=1,  # Start with ID 1
            signed_pre_key_signature=dummy_signature,
            identity_key_private=identity_private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            identity_key_public=identity_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            platform="android"
        )
        return self._device_to_store(device)

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
        store.signed_pre_key = device.signed_pre_key
        store.signed_pre_key_id = device.signed_pre_key_id
        store.signed_pre_key_signature = device.signed_pre_key_signature
        store.identity_key_private = device.identity_key_private
        store.identity_key_public = device.identity_key_public
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
