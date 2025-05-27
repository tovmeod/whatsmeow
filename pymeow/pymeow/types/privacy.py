"""
Privacy-related types for PyMeow.
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Optional

from .jid import JID

class PrivacySetting(str, Enum):
    """Privacy settings for various aspects of the account."""
    PROFILE = "profile"
    LAST_SEEN = "last"
    STATUS = "status"
    PROFILE_PHOTO = "profile_photo"
    READ_RECEIPTS = "read_receipts"
    GROUPS_ADD = "group_add"
    STATUS_VIEW = "status_view"
    ONLINE_STATUS = "online"
    CALL_ADD = "call_add"
    BLOCKED = "blocked"

class PrivacyValue(str, Enum):
    """Possible values for privacy settings."""
    ALL = "all"
    CONTACTS = "contacts"
    CONTACTS_EXCEPT = "contacts_except"
    NOBODY = "none"
    MATCH_LAST_SEEN = "match_last_seen"

@dataclass
class PrivacySettings:
    """Represents the privacy settings for an account."""
    profile: PrivacyValue = PrivacyValue.ALL
    last_seen: PrivacyValue = PrivacyValue.ALL
    status: PrivacyValue = PrivacyValue.ALL
    profile_photo: PrivacyValue = PrivacyValue.ALL
    read_receipts: PrivacyValue = PrivacyValue.ALL
    groups_add: PrivacyValue = PrivacyValue.ALL
    status_view: PrivacyValue = PrivacyValue.ALL
    online_status: PrivacyValue = PrivacyValue.ALL
    call_add: PrivacyValue = PrivacyValue.ALL
    blocked: PrivacyValue = PrivacyValue.ALL

    # For settings that allow exceptions
    profile_exceptions: List[JID] = None
    last_seen_exceptions: List[JID] = None
    status_exceptions: List[JID] = None
    profile_photo_exceptions: List[JID] = None
    read_receipts_exceptions: List[JID] = None
    groups_add_exceptions: List[JID] = None
    status_view_exceptions: List[JID] = None
    online_status_exceptions: List[JID] = None
    call_add_exceptions: List[JID] = None
    blocked_exceptions: List[JID] = None

    def __post_init__(self):
        if self.profile_exceptions is None:
            self.profile_exceptions = []
        if self.last_seen_exceptions is None:
            self.last_seen_exceptions = []
        if self.status_exceptions is None:
            self.status_exceptions = []
        if self.profile_photo_exceptions is None:
            self.profile_photo_exceptions = []
        if self.read_receipts_exceptions is None:
            self.read_receipts_exceptions = []
        if self.groups_add_exceptions is None:
            self.groups_add_exceptions = []
        if self.status_view_exceptions is None:
            self.status_view_exceptions = []
        if self.online_status_exceptions is None:
            self.online_status_exceptions = []
        if self.call_add_exceptions is None:
            self.call_add_exceptions = []
        if self.blocked_exceptions is None:
            self.blocked_exceptions = []

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PrivacySettings':
        """Create PrivacySettings from a dictionary."""
        settings = cls()
        for key, value in data.items():
            if hasattr(settings, key):
                if key.endswith('_exceptions') and isinstance(value, list):
                    setattr(settings, key, [JID.from_string(jid) if isinstance(jid, str) else jid for jid in value])
                elif hasattr(PrivacyValue, value.upper()):
                    setattr(settings, key, PrivacyValue(value))
        return settings

    def to_dict(self) -> Dict[str, Any]:
        """Convert PrivacySettings to a dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if key.endswith('_exceptions'):
                result[key] = [str(jid) for jid in value]
            elif isinstance(value, PrivacyValue):
                result[key] = value.value
        return result
