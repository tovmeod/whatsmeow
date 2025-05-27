"""
Python port of data types from whatsmeow.

Go equivalent: types/ directory, particularly:
- types/whatsapp.go
- types/message.go
- types/contact.go
- types/group.go
- types/jid.go

This module defines the core data structures used throughout the pymeow
library, including messages, contacts, groups, and other WhatsApp entities.
"""
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from .generated.waMsgTransport import WAMsgTransport_pb2

# Alias for backward compatibility
ProtoMessage = WAMsgTransport_pb2.MessageTransport

class MessageType(Enum):
    """Types of WhatsApp messages."""
    TEXT = auto()
    IMAGE = auto()
    VIDEO = auto()
    AUDIO = auto()
    DOCUMENT = auto()
    STICKER = auto()
    LOCATION = auto()
    CONTACT = auto()
    CONTACT_ARRAY = auto()
    REACTION = auto()
    UNKNOWN = auto()

class MessageStatus(Enum):
    """Status of a WhatsApp message."""
    PENDING = auto()
    SERVER_ACK = auto()
    DELIVERY_ACK = auto()
    READ = auto()
    PLAYED = auto()
    ERROR = auto()

class PrivacySetting(Enum):
    """Privacy settings for the user's account."""
    ALL = "all"
    CONTACTS = "contacts"
    CONTACT_BLACKLIST = "blacklist"
    MATCH_LAST_SEEN = "match_last_seen"
    NONE = "none"

__all__ = ['MessageType', 'MessageStatus', 'PrivacySetting', 'Contact', 'Chat', 'Reaction', 'ProtoMessage']

@dataclass
class Contact:
    """Represents a WhatsApp contact."""
    jid: str
    name: Optional[str] = None
    notify: Optional[str] = None
    short_name: Optional[str] = None
    is_me: bool = False
    is_contact: bool = False
    is_verified: bool = False
    is_wid: bool = False
    is_enterprise: bool = False
    is_high_level_verified: bool = False
    status: Optional[str] = None
    status_timestamp: Optional[datetime] = None
    push_name: Optional[str] = None
    labels: List[str] = field(default_factory=list)

@dataclass
class Chat:
    """Represents a WhatsApp chat."""
    jid: str
    name: str
    unread_count: int = 0
    is_read_only: bool = False
    is_muted: bool = False
    is_marked_unread: bool = False
    is_group: bool = False
    is_announce: bool = False
    is_community: bool = False
    is_community_announce: bool = False
    is_default_sub_group: bool = False
    is_parent_group: bool = False
    is_my_contact: bool = False
    is_user: bool = False
    is_broadcast: bool = False
    is_me: bool = False
    is_blocked: bool = False
    last_message: Optional['Message'] = None
    timestamp: Optional[datetime] = None
    unread_mentions: int = 0
    unread_mention_count: int = 0
    has_new_msg_reaction: bool = False

@dataclass
class Reaction:
    """Represents a reaction to a message."""
    message_id: str
    sender_jid: str
    emoji: str
    timestamp: datetime
    is_removed: bool = False

# Message class has been moved to message.py to avoid circular imports

@dataclass
class GroupInfo:
    """Represents information about a WhatsApp group."""
    jid: str
    name: str
    owner: str
    creation_time: datetime
    subject_owner: Optional[str] = None
    subject_time: Optional[datetime] = None
    description: Optional[str] = None
    description_id: Optional[str] = None
    description_owner: Optional[str] = None
    description_time: Optional[datetime] = None
    locked: bool = False
    announce: bool = False
    ephemeral_duration: int = 0
    participants: List[Dict[str, Any]] = field(default_factory=list)
    pending_requests: List[Dict[str, Any]] = field(default_factory=list)
    is_parent: bool = False
    is_default_sub_group: bool = False
    parent_group_id: Optional[str] = None
    is_community: bool = False
    is_announce: bool = False

@dataclass
class UserInfo:
    """Represents information about the current user."""
    jid: str
    push_name: str
    wid: str
    platform: str
    phone: str
    phone_cc: str
    phone_number: str
    is_business: bool
    is_enterprise: bool
    is_high_level_verified: bool
    status: Optional[str] = None
    picture_id: Optional[str] = None
    picture_url: Optional[str] = None
    picture_ts: Optional[int] = None
    picture_hash: Optional[str] = None
