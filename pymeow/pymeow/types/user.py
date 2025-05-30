"""
User-related types for PyMeow.

Port of whatsmeow/types/user.go
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import time
from datetime import datetime
from enum import Enum

from ..generated.waVnameCert import WAWebProtobufsVnameCert_pb2
from .jid import JID


@dataclass
class VerifiedName:
    """Contains verified WhatsApp business details."""
    certificate: Optional[WAWebProtobufsVnameCert_pb2.VerifiedNameCertificate] = None
    details: Optional[WAWebProtobufsVnameCert_pb2.VerifiedNameCertificate.Details] = None


@dataclass
class UserInfo:
    """Contains info about a WhatsApp user."""
    verified_name: Optional[VerifiedName] = None
    status: str = ""
    picture_id: str = ""
    devices: List[JID] = field(default_factory=list)


@dataclass
class BotListInfo:
    """Information about a bot in a list."""
    bot_jid: JID = field(default_factory=lambda: JID(user="", server=""))
    persona_id: str = ""


@dataclass
class BotProfileCommand:
    """Command information for a bot profile."""
    name: str = ""
    description: str = ""


@dataclass
class BotProfileInfo:
    """Profile information for a bot."""
    jid: JID = field(default_factory=lambda: JID(user="", server=""))
    name: str = ""
    attributes: str = ""
    description: str = ""
    category: str = ""
    is_default: bool = False
    prompts: List[str] = field(default_factory=list)
    persona_id: str = ""
    commands: List[BotProfileCommand] = field(default_factory=list)
    commands_description: str = ""


@dataclass
class ProfilePictureInfo:
    """Contains the ID and URL for a WhatsApp user's profile picture or group's photo."""
    url: str = ""  # The full URL for the image, can be downloaded with a simple HTTP request.
    id: str = ""   # The ID of the image. This is the same as UserInfo.PictureID.
    type: str = ""  # The type of image. Known types include "image" (full res) and "preview" (thumbnail).
    direct_path: str = ""  # The path to the image, probably not very useful


@dataclass
class ContactInfo:
    """Contains the cached names of a WhatsApp user."""
    found: bool = False
    first_name: str = ""
    full_name: str = ""
    push_name: str = ""
    business_name: str = ""


@dataclass
class LocalChatSettings:
    """Contains the cached local settings for a chat."""
    found: bool = False
    muted_until: Optional[datetime] = None
    pinned: bool = False
    archived: bool = False


@dataclass
class IsOnWhatsAppResponse:
    """Contains information received in response to checking if a phone number is on WhatsApp."""
    query: str = ""  # The query string used
    jid: JID = field(default_factory=lambda: JID(user="", server=""))  # The canonical user ID
    is_in: bool = False  # Whether the phone is registered or not.
    verified_name: Optional[VerifiedName] = None  # If the phone is a business, the verified business details.


@dataclass
class BusinessMessageLinkTarget:
    """Contains the info that is found using a business message link."""
    jid: JID = field(default_factory=lambda: JID(user="", server=""))  # The JID of the business.
    push_name: str = ""  # The notify / push name of the business.
    verified_name: str = ""  # The verified business name.
    is_signed: bool = False  # Some boolean, seems to be true?
    verified_level: str = ""  # I guess the level of verification, starting from "unknown".
    message: str = ""  # The message that WhatsApp clients will pre-fill in the input box when clicking the link.


@dataclass
class ContactQRLinkTarget:
    """Contains the info that is found using a contact QR link."""
    jid: JID = field(default_factory=lambda: JID(user="", server=""))  # The JID of the user.
    type: str = ""  # Might always be "contact".
    push_name: str = ""  # The notify / push name of the user.


class PrivacySetting(str, Enum):
    """An individual setting value in the user's privacy settings."""
    UNDEFINED = ""
    ALL = "all"
    CONTACTS = "contacts"
    CONTACT_BLACKLIST = "contact_blacklist"
    MATCH_LAST_SEEN = "match_last_seen"
    KNOWN = "known"
    NONE = "none"


class PrivacySettingType(str, Enum):
    """The type of privacy setting."""
    GROUP_ADD = "groupadd"  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    LAST_SEEN = "last"  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    STATUS = "status"  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    PROFILE = "profile"  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    READ_RECEIPTS = "readreceipts"  # Valid values: PrivacySetting.ALL, PrivacySetting.NONE
    ONLINE = "online"  # Valid values: PrivacySetting.ALL, PrivacySetting.MATCH_LAST_SEEN
    CALL_ADD = "calladd"  # Valid values: PrivacySetting.ALL, PrivacySetting.KNOWN


@dataclass
class PrivacySettings:
    """Contains the user's privacy settings."""
    group_add: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    last_seen: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    status: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    profile: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST, PrivacySetting.NONE
    read_receipts: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.NONE
    call_add: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.KNOWN
    online: PrivacySetting = PrivacySetting.UNDEFINED  # Valid values: PrivacySetting.ALL, PrivacySetting.MATCH_LAST_SEEN


class StatusPrivacyType(str, Enum):
    """The type of list in StatusPrivacy."""
    CONTACTS = "contacts"  # Statuses are sent to all contacts.
    BLACKLIST = "blacklist"  # Statuses are sent to all contacts, except the ones on the list.
    WHITELIST = "whitelist"  # Statuses are only sent to users on the list.


@dataclass
class StatusPrivacy:
    """Contains the settings for who to send status messages to by default."""
    type: StatusPrivacyType = StatusPrivacyType.CONTACTS
    list: List[JID] = field(default_factory=list)
    is_default: bool = False


@dataclass
class Blocklist:
    """Contains the user's current list of blocked users."""
    d_hash: str = ""  # TODO is this just a timestamp?
    jids: List[JID] = field(default_factory=list)


@dataclass
class BusinessHoursConfig:
    """Contains business operating hours of a WhatsApp business."""
    day_of_week: str = ""
    mode: str = ""
    open_time: str = ""
    close_time: str = ""


@dataclass
class Category:
    """Contains a WhatsApp business category."""
    id: str = ""
    name: str = ""


@dataclass
class BusinessProfile:
    """Contains the profile information of a WhatsApp business."""
    jid: JID = field(default_factory=lambda: JID(user="", server=""))
    address: str = ""
    email: str = ""
    categories: List[Category] = field(default_factory=list)
    profile_options: Dict[str, str] = field(default_factory=dict)
    business_hours_time_zone: str = ""
    business_hours: List[BusinessHoursConfig] = field(default_factory=list)
