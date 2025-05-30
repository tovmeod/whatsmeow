"""
WhatsApp privacy settings handling.

Port of whatsmeow/privacysettings.go
"""
from enum import Enum
from typing import Optional
from dataclasses import dataclass

class PrivacySettingType(str, Enum):
    """Types of WhatsApp privacy settings."""
    GROUP_ADD = "groupadd"
    LAST_SEEN = "last"
    STATUS = "status"
    PROFILE = "profile"
    READ_RECEIPTS = "readreceipts"
    ONLINE = "online"
    CALL_ADD = "calladd"

class PrivacySetting(str, Enum):
    """Values for privacy settings."""
    ALL = "all"
    CONTACTS = "contacts"
    CONTACT_BLACKLIST = "contact-blacklist"
    NONE = "none"
    MATCH_LAST_SEEN = "match-last-seen"

@dataclass
class PrivacySettings:
    """Represents the privacy settings for an account."""
    group_add: PrivacySetting = PrivacySetting.ALL
    last_seen: PrivacySetting = PrivacySetting.ALL
    status: PrivacySetting = PrivacySetting.ALL
    profile: PrivacySetting = PrivacySetting.ALL
    read_receipts: PrivacySetting = PrivacySetting.ALL
    online: PrivacySetting = PrivacySetting.ALL
    call_add: PrivacySetting = PrivacySetting.ALL
