"""
Types used throughout the PyMeow library.

This module exports various types used for type hints and data validation.
"""
# Import and expose presence-related types
# Message related types
from .events.events import Message

# Group types
from .group import (
    GroupInfo,
    GroupLinkChangeType,
    GroupParticipant,
    GroupUnlinkReason,
)

# Import JID type
from .jid import JID
from .message import MessageInfo

# Newsletter types
from .newsletter import (
    NewsletterMuteState,
    NewsletterReactionsMode,
    NewsletterRole,
    NewsletterSettings,
    NewsletterState,
)
from .presence import (
    ChatPresence,
    ChatPresenceEvent,
    ChatPresenceMedia,
    Presence,
    PresenceEvent,
    ReceiptType,
)

# User types
from .user import (
    Blocklist,
    BotListInfo,
    BotProfileCommand,
    BotProfileInfo,
    BusinessHoursConfig,
    BusinessMessageLinkTarget,
    BusinessProfile,
    Category,
    ContactInfo,
    ContactQRLinkTarget,
    IsOnWhatsAppResponse,
    LocalChatSettings,
    PrivacySetting,
    PrivacySettings,
    PrivacySettingType,
    ProfilePictureInfo,
    StatusPrivacy,
    StatusPrivacyType,
    UserInfo,
    VerifiedName,
)

__all__ = [
    'JID',
    'Blocklist',
    'BotListInfo',
    'BotProfileCommand',
    'BotProfileInfo',
    'BusinessHoursConfig',
    'BusinessMessageLinkTarget',
    'BusinessProfile',
    'Category',
    'ChatPresence',
    'ChatPresenceEvent',
    'ChatPresenceMedia',
    'ContactInfo',
    'ContactQRLinkTarget',
    'GroupInfo',
    'GroupLinkChangeType',
    'GroupParticipant',
    'GroupUnlinkReason',
    'IsOnWhatsAppResponse',
    'LocalChatSettings',
    'Message',
    'MessageInfo',
    'NewsletterMuteState',
    'NewsletterReactionsMode',
    'NewsletterRole',
    'NewsletterSettings',
    'NewsletterState',
    'Presence',
    'PresenceEvent',
    'PrivacySetting',
    'PrivacySetting',
    'PrivacySettingType',
    'PrivacySettings',
    'PrivacySettings',
    'ProfilePictureInfo',
    'ReceiptType',
    'StatusPrivacy',
    'StatusPrivacy',
    'StatusPrivacyType',
    'UserInfo',
    'VerifiedName',
]
