"""
WhatsApp privacy settings handling.

Port of whatsmeow/privacysettings.go
"""
from enum import Enum
from typing import Dict, List, Optional

from .generated.waCommon import WACommon_pb2

class PrivacySettingType(Enum):
    """Types of WhatsApp privacy settings."""
    LAST_SEEN = "last_seen"
    ONLINE = "online"
    PROFILE_PHOTO = "profile_photo"
    STATUS = "status"
    READ_RECEIPTS = "read_receipts"
    GROUPS = "groups"
    BLOCKED = "blocked"

class PrivacyValue(Enum):
    """Values for privacy settings."""
    UNDEFINED = "undefined"
    ALL = "all"
    CONTACTS = "contacts"
    CONTACT_BLACKLIST = "contact_blacklist"
    NONE = "none"
    MATCHING_LAST_SEEN = "matching_last_seen"

class PrivacySettings:
    """Manages WhatsApp privacy settings."""

    def __init__(self):
        self._settings: Dict[PrivacySettingType, PrivacyValue] = {}
        self._excluded_list: Dict[PrivacySettingType, List[str]] = {}

    def set_privacy(self, setting: PrivacySettingType, value: PrivacyValue, excluded_jids: List[str] = None) -> None:
        """Set a privacy setting."""
        self._settings[setting] = value
        if excluded_jids is not None:
            self._excluded_list[setting] = excluded_jids

    def get_privacy(self, setting: PrivacySettingType) -> tuple[Optional[PrivacyValue], List[str]]:
        """Get a privacy setting and its excluded JIDs."""
        return (
            self._settings.get(setting),
            self._excluded_list.get(setting, [])
        )
