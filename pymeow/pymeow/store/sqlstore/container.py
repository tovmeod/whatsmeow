import logging
import os
import struct
from typing import Optional, List, TYPE_CHECKING

from tortoise import Tortoise, transactions
from tortoise.exceptions import DoesNotExist

from .config import get_tortoise_config
from .models.device import DeviceModel
from ...util.keys.keypair import KeyPair, PreKey

if TYPE_CHECKING:
    from ...store.store import Device

logger = logging.getLogger(__name__)

class Container:
    """Database container managing WhatsApp store operations"""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._initialized = False

    async def ainit(self) -> 'Container':
        """Initialize Tortoise ORM connection"""
        if self._initialized:
            return self

        config = get_tortoise_config(self.db_url)
        await Tortoise.init(config)
        await Tortoise.generate_schemas()
        self._initialized = True
        logger.info("Database initialized successfully")
        return self

    async def close(self) -> None:
        """Close database connections"""
        if self._initialized:
            await Tortoise.close_connections()
            self._initialized = False
            logger.info("Database connections closed")

    async def get_all_devices(self) -> List['Device']:
        """Get all registered devices"""
        devices = await DeviceModel.all()
        return [self._device_to_store(device) for device in devices]

    async def get_first_device(self) -> Optional['Device']:
        """Get the first available device, create one if none exist"""
        try:
            device = await DeviceModel.first()
            if device:
                return self._device_to_store(device)
            else:
                return await self.new_device("new_device@temp.com")
        except DoesNotExist:
            # Create a new device if none exist (like Go implementation)
            return await self.new_device("new_device@temp.com")

    async def get_device(self, jid: str) -> Optional['Device']:
        """Get device by JID"""
        try:
            device = await DeviceModel.get(id=jid)
            return self._device_to_store(device)
        except DoesNotExist:
            return None

    async def new_device(self, jid: str) -> 'Device':
        """Create a new device with proper default values"""
        # Generate noise key
        noise_key = KeyPair.generate()

        # Generate identity key pair
        identity_key = KeyPair.generate()

        # Generate signed pre-key using the identity key (like Go does)
        signed_pre_key = identity_key.create_signed_pre_key(1)

        # Generate registration ID (random 32-bit integer)
        the_random_bytes: bytes = os.urandom(4)
        registration_id = struct.unpack(">I", the_random_bytes)[0]

        # Generate ADV secret key
        adv_key = os.urandom(32)  # 32 bytes for ADV secret key

        device = await DeviceModel.create(
            jid=jid,  # Changed from 'id' to 'jid'
            registration_id=registration_id,
            # Store full private keys (not separate public/private)
            noise_key=noise_key.priv,
            identity_key=identity_key.priv,
            signed_pre_key=signed_pre_key.priv,  # Store private key part
            signed_pre_key_id=signed_pre_key.key_id,
            signed_pre_key_sig=signed_pre_key.signature,  # Changed from 'signed_pre_key_signature'
            # ADV fields
            adv_key=adv_key,
            adv_details=b'',  # Empty for now
            adv_account_sig=b'',  # Empty for now
            adv_account_sig_key=b'',  # Empty for now
            adv_device_sig=b'',  # Empty for now
            # Optional fields with defaults
            lid=None,
            facebook_uuid=None,
            platform="android",
            business_name="",
            push_name=""
        )

        store = self._device_to_store(device)
        # Set the full KeyPair objects in the store (since _device_to_store only gets private keys)
        store.noise_key = noise_key
        store.identity_key = identity_key
        store.signed_pre_key = signed_pre_key

        return store

    async def put_device(self, store: 'Device') -> None:
        """Save device to database"""
        await self._store_to_device(store).update_or_create()

    async def delete_device(self, jid: str) -> None:
        """Delete device and all associated data"""
        async with transactions.in_transaction():
            # Delete device and cascade to related tables
            await DeviceModel.filter(id=jid).delete()
            # Additional cleanup for related tables
            from .models.session import IdentityKeyModel, SessionModel, PreKeyModel, SenderKeyModel
            from .models.contacts import ContactModel
            from .models.appstate import AppStateSyncKeyModel, AppStateVersionModel

            await IdentityKeyModel.filter(our_jid=jid).delete()
            await SessionModel.filter(our_jid=jid).delete()
            await PreKeyModel.filter(jid=jid).delete()
            await SenderKeyModel.filter(our_jid=jid).delete()
            await ContactModel.filter(our_jid=jid).delete()
            await AppStateSyncKeyModel.filter(jid=jid).delete()
            await AppStateVersionModel.filter(jid=jid).delete()

    def _device_to_store(self, device: DeviceModel) -> 'Device':
        """Convert Device model to DeviceStore"""
        from ...store.store import Device
        store = Device(self, device.jid)
        store.lid = device.lid if device.lid else ""
        store.registration_id = device.registration_id
        if device.facebook_uuid:
            store.facebook_uuid = device.facebook_uuid

        # Reconstruct noise key from stored private key
        if device.noise_key:
            store.noise_key = KeyPair.from_private_key(device.noise_key)

        # Reconstruct identity key from stored private key
        if device.identity_key:
            store.identity_key = KeyPair.from_private_key(device.identity_key)

        # Reconstruct signed pre-key
        if device.signed_pre_key and device.signed_pre_key_id and device.signed_pre_key_sig:
            # Create KeyPair from the stored private key
            key_pair = KeyPair.from_private_key(device.signed_pre_key)
            store.signed_pre_key = PreKey(
                key_pair=key_pair,
                key_id=device.signed_pre_key_id,
                signature=device.signed_pre_key_sig
            )

        # ADV (Account Device Verification) fields
        store.adv_secret_key = device.adv_key if device.adv_key else b''
        # Note: You might need to add more ADV fields to your Device class:
        # store.adv_details = device.adv_details
        # store.adv_account_sig = device.adv_account_sig
        # store.adv_account_sig_key = device.adv_account_sig_key
        # store.adv_device_sig = device.adv_device_sig

        # Only set fields that exist in the Go version
        store.platform = device.platform
        store.business_name = device.business_name
        store.push_name = device.push_name

        return store

    def _store_to_device(self, store: 'Device') -> DeviceModel:
        """Convert DeviceStore to Device model"""
        device = DeviceModel()

        # Basic device info
        device.jid = store.jid if store.jid else ""
        device.lid = store.lid if hasattr(store, 'lid') and store.lid else None
        device.registration_id = store.registration_id

        # Facebook UUID
        if hasattr(store, 'facebook_uuid'):
            device.facebook_uuid = store.facebook_uuid

        # Store noise key private key bytes
        if store.noise_key:
            device.noise_key = store.noise_key.priv

        # Store identity key private key bytes
        if store.identity_key:
            device.identity_key = store.identity_key.priv

        # Store signed pre-key info
        if store.signed_pre_key:
            device.signed_pre_key = store.signed_pre_key.priv
            device.signed_pre_key_id = store.signed_pre_key.key_id
            device.signed_pre_key_sig = store.signed_pre_key.signature

        # ADV fields
        if hasattr(store, 'adv_secret_key'):
            device.adv_key = store.adv_secret_key
        # Add other ADV fields as needed based on your Device class

        # Platform info
        device.platform = store.platform if store.platform else ""
        device.business_name = store.business_name if store.business_name else ""
        device.push_name = store.push_name if store.push_name else ""

        return device
