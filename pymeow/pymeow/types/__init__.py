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
from .message import Message, MessageType, MessageStatus, MessageInfo, MessageKey
from .message_status import MessageStatusType, MessageStatusInfo, MessageStatusUpdate, MessageStatusError
from .receipts import ReceiptType, ReceiptInfo, ReceiptBatch, ReadReceiptRequest

# Contact and chat types
from .contact import Contact, ContactStatus, ContactAction
from .chat import Chat

# Group types
from .group import (
    GroupLinkChangeType,
    GroupUnlinkReason,
    GroupParticipant,
    GroupInfo,
    GroupLinkInfo
)

# Privacy types
from .privacy import PrivacySetting, PrivacyValue, PrivacySettings

# Call types
from .call import CallType, CallState, CallParticipant, CallInfo

# Call event types
from .call_events import (
    CallMediaType,
    CallOfferEvent,
    CallRejectEvent,
    CallTerminateEvent,
)

# Location types
from .location import (
    LocationAccuracy,
    LocationType,
    Coordinates,
    LocationInfo,
    LiveLocationInfo,
    PlaceInfo,
    VenueInfo,
)

# Payment types
from .payment import (
    PaymentCurrency,
    PaymentStatus,
    PaymentMethodType,
    Money,
    PaymentMethod,
    PaymentInfo,
    PaymentRequest,
)

# Reaction types
from .reaction import (
    ReactionAction,
    ReactionInfo,
    ReactionAggregation,
    ReactionSync,
    ReactionSettings,
)

# Expiration types
from .expiration import ExpirationType, ExpirationInfo

# Status (Stories) types
from .status import (
    StatusType,
    StatusPrivacy,
    StatusInfo,
    StatusViewerInfo,
    StatusPrivacySettings,
    StoryReplyInfo,
)

# Newsletter types
from .newsletter import (
    NewsletterState,
    NewsletterRole,
    NewsletterMuteState,
    NewsletterReactionsMode,
    NewsletterVerificationStatus,
    NewsletterSettings,
    NewsletterMessageInfo,
    NewsletterReaction,
)

# Business types
from .business import (
    BusinessCategory,
    BusinessHoursDay,
    BusinessHoursTime,
    BusinessHoursRange,
    BusinessHoursSchedule,
    BusinessProfile,
)

from .business_templates import (
    TemplateComponentType,
    TemplateButtonType,
    TemplateFormat,
    TemplateCategory,
    TemplateStatus,
    TemplateLanguage,
    TemplateButton,
    TemplateComponent,
    MessageTemplate,
    TemplateMessage,
)

from .commerce import (
    CurrencyCode,
    ProductAvailability,
    ProductCondition,
    ProductPrice,
    ProductImage,
    ProductVariant,
    Product,
    Catalog,
    CartItem,
    Cart,
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
    'MessageKey',
    'MessageStatus',
    'MessageType',
    'MessageStatusType',
    'MessageStatusInfo',
    'MessageStatusUpdate',
    'MessageStatusError',

    # Receipts
    'ReceiptType',
    'ReceiptInfo',
    'ReceiptBatch',
    'ReadReceiptRequest',

    # Contacts
    'Contact',
    'ContactStatus',
    'ContactAction',

    # Chats
    'Chat',

    # Groups
    'GroupLinkChangeType',
    'GroupUnlinkReason',
    'GroupParticipant',
    'GroupInfo',
    'GroupLinkInfo',

    # Privacy
    'PrivacySetting',
    'PrivacyValue',
    'PrivacySettings',

    # Calls
    'CallType',
    'CallState',
    'CallParticipant',
    'CallInfo',

    # Call Events
    'CallMediaType',
    'CallOfferEvent',
    'CallRejectEvent',
    'CallTerminateEvent',

    # Location
    'LocationAccuracy',
    'LocationType',
    'Coordinates',
    'LocationInfo',
    'LiveLocationInfo',
    'PlaceInfo',
    'VenueInfo',

    # Payments
    'PaymentCurrency',
    'PaymentStatus',
    'PaymentMethodType',
    'Money',
    'PaymentMethod',
    'PaymentInfo',
    'PaymentRequest',

    # Reactions
    'ReactionAction',
    'ReactionInfo',
    'ReactionAggregation',
    'ReactionSync',
    'ReactionSettings',
    
    # Expiration
    'ExpirationType',
    'ExpirationInfo',

    # Status (Stories)
    'StatusType',
    'StatusPrivacy',
    'StatusInfo',
    'StatusViewerInfo',
    'StatusPrivacySettings',
    'StoryReplyInfo',

    # Newsletter
    'NewsletterState',
    'NewsletterRole',
    'NewsletterMuteState',
    'NewsletterReactionsMode',
    'NewsletterVerificationStatus',
    'NewsletterSettings',
    'NewsletterMessageInfo',
    'NewsletterReaction',
]
