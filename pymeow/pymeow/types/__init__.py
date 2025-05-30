"""
Types used throughout the PyMeow library.

This module exports various types used for type hints and data validation.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

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
    # JID
    'JID',

    # Presence
    'Presence',
    'ChatPresence',
    'ChatPresenceMedia',
    'PresenceEvent',
    'ChatPresenceEvent',

    # Message
    'Message',
    'MessageInfo',

    # Receipts
    'ReceiptType',

    # Groups
    'GroupLinkChangeType',
    'GroupUnlinkReason',
    'GroupParticipant',
    'GroupInfo',

    # Privacy
    'PrivacySetting',
    'PrivacySettings',

    # Status (Stories)
    'StatusPrivacy',

    # Newsletter
    'NewsletterState',
    'NewsletterRole',
    'NewsletterMuteState',
    'NewsletterReactionsMode',
    'NewsletterSettings',

    # User types
    'VerifiedName',
    'UserInfo',
    'BotListInfo',
    'BotProfileCommand',
    'BotProfileInfo',
    'ProfilePictureInfo',
    'ContactInfo',
    'LocalChatSettings',
    'IsOnWhatsAppResponse',
    'BusinessMessageLinkTarget',
    'ContactQRLinkTarget',
    'PrivacySetting',
    'PrivacySettingType',
    'PrivacySettings',
    'StatusPrivacyType',
    'StatusPrivacy',
    'Blocklist',
    'BusinessHoursConfig',
    'Category',
    'BusinessProfile',
]
