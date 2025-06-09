"""
Types used throughout the PyMeow library.

This module exports various types used for type hints and data validation.
"""
# Import and expose presence-related types
from .presence import (
    Presence,
    ChatPresence,
    ChatPresenceMedia,
    PresenceEvent,
    ChatPresenceEvent,
)

# Import JID type
from .jid import JID

# Message related types
from .events.events import Message
from .message import MessageInfo
from .presence import ReceiptType

# Group types
from .group import (
    GroupLinkChangeType,
    GroupUnlinkReason,
    GroupParticipant,
    GroupInfo,
)




# Newsletter types
from .newsletter import (
    NewsletterState,
    NewsletterRole,
    NewsletterMuteState,
    NewsletterReactionsMode,
    NewsletterSettings,
)

# User types
from .user import (
    VerifiedName,
    UserInfo,
    BotListInfo,
    BotProfileCommand,
    BotProfileInfo,
    ProfilePictureInfo,
    ContactInfo,
    LocalChatSettings,
    IsOnWhatsAppResponse,
    BusinessMessageLinkTarget,
    ContactQRLinkTarget,
    PrivacySetting,
    PrivacySettingType,
    PrivacySettings,
    StatusPrivacyType,
    StatusPrivacy,
    Blocklist,
    BusinessHoursConfig,
    Category,
    BusinessProfile,
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
