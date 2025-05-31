"""
App state keys management for WhatsApp.

Port of whatsmeow/appstate/keys.go
"""
import base64
import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from ..store import Device
from ..util.hkdfutil import expand_hmac
import logging

# WAPatchName represents a type of app state patch.
class WAPatchName(str):
    """Types of app state patches."""

    # WAPatchCriticalBlock contains the user's settings like push name and locale.
    CRITICAL_BLOCK = "critical_block"

    # WAPatchCriticalUnblockLow contains the user's contact list.
    CRITICAL_UNBLOCK_LOW = "critical_unblock_low"

    # WAPatchRegularLow contains some local chat settings like pin, archive status, and the setting of whether to unarchive chats when messages come in.
    REGULAR_LOW = "regular_low"

    # WAPatchRegularHigh contains more local chat settings like mute status and starred messages.
    REGULAR_HIGH = "regular_high"

    # WAPatchRegular contains protocol info about app state patches like key expiration.
    REGULAR = "regular"

# AllPatchNames contains all currently known patch state names.
ALL_PATCH_NAMES = [
    WAPatchName.CRITICAL_BLOCK,
    WAPatchName.CRITICAL_UNBLOCK_LOW,
    WAPatchName.REGULAR_HIGH,
    WAPatchName.REGULAR,
    WAPatchName.REGULAR_LOW
]

# Constants for the first part of app state indexes.
INDEX_MUTE = "mute"
INDEX_PIN = "pin_v1"
INDEX_ARCHIVE = "archive"
INDEX_CONTACT = "contact"
INDEX_CLEAR_CHAT = "clearChat"
INDEX_DELETE_CHAT = "deleteChat"
INDEX_STAR = "star"
INDEX_DELETE_MESSAGE_FOR_ME = "deleteMessageForMe"
INDEX_MARK_CHAT_AS_READ = "markChatAsRead"
INDEX_SETTING_PUSH_NAME = "setting_pushName"
INDEX_SETTING_UNARCHIVE_CHATS = "setting_unarchiveChats"
INDEX_USER_STATUS_MUTE = "userStatusMute"
INDEX_LABEL_EDIT = "label_edit"
INDEX_LABEL_ASSOCIATION_CHAT = "label_jid"
INDEX_LABEL_ASSOCIATION_MESSAGE = "label_message"

logger = logging.getLogger(__name__)

@dataclass
class ExpandedAppStateKeys:
    """Expanded app state keys derived from the original key data."""

    index: bytes
    value_encryption: bytes
    value_mac: bytes
    snapshot_mac: bytes
    patch_mac: bytes

class Processor:
    """Processor for app state patches."""

    def __init__(self, store: Device, log: Optional[logging.Logger] = None):
        """
        Initialize a new app state processor.

        Args:
            store: The device to use for retrieving keys
            log: Logger for debug messages
        """
        self.key_cache: Dict[str, ExpandedAppStateKeys] = {}
        self.key_cache_lock = asyncio.Lock()
        self.store = store

    @staticmethod
    def expand_app_state_keys(key_data: bytes) -> ExpandedAppStateKeys:
        """
        Expand app state keys using HKDF.

        Args:
            key_data: The raw key data

        Returns:
            Expanded keys for various cryptographic operations
        """
        app_state_key_expanded = expand_hmac(key_data, b"WhatsApp Mutation Keys", 160)
        return ExpandedAppStateKeys(
            index=app_state_key_expanded[0:32],
            value_encryption=app_state_key_expanded[32:64],
            value_mac=app_state_key_expanded[64:96],
            snapshot_mac=app_state_key_expanded[96:128],
            patch_mac=app_state_key_expanded[128:160]
        )

    async def get_app_state_key(self, key_id: bytes) -> tuple[ExpandedAppStateKeys, Optional[Exception]]:
        """
        Get the expanded app state keys for the given key ID.

        Args:
            key_id: The key ID to look up

        Returns:
            A tuple of (expanded keys, error)
        """
        key_cache_id = base64.b64encode(key_id).decode('ascii')

        async with self.key_cache_lock:
            keys = self.key_cache.get(key_cache_id)
            if keys is None:
                try:
                    key_data = await self.store.get_app_state_sync_key(key_id)
                    if key_data is not None:
                        keys = self.expand_app_state_keys(key_data.data)
                        self.key_cache[key_cache_id] = keys
                        return keys, None
                    else:
                        from .errors import ErrKeyNotFound
                        return None, ErrKeyNotFound()
                except Exception as err:
                    return None, err
            return keys, None

    async def get_missing_key_ids(self, patch_list: Any) -> List[bytes]:
        """
        Get a list of key IDs that are missing from the store.

        Args:
            patch_list: The patch list to check

        Returns:
            A list of missing key IDs
        """
        cache: Dict[str, bool] = {}
        missing_keys: List[bytes] = []

        async def check_missing(key_id: Optional[bytes]):
            if key_id is None:
                return

            string_key_id = base64.b64encode(key_id).decode('ascii')
            if string_key_id in cache:
                return

            try:
                key_data = await self.store.get_app_state_sync_key(key_id)
                missing = key_data is None
                cache[string_key_id] = missing
                if missing:
                    missing_keys.append(key_id)
            except Exception as err:
                logger.warning(f"Error fetching key {key_id.hex()} while checking if it's missing: {err}")

        if patch_list.snapshot is not None:
            await check_missing(patch_list.snapshot.key_id.id if patch_list.snapshot.key_id else None)
            for record in patch_list.snapshot.records:
                await check_missing(record.key_id.id if record.key_id else None)

        for patch in patch_list.patches:
            await check_missing(patch.key_id.id if patch.key_id else None)

        return missing_keys
