"""
Chat-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any

from .jid import JID

class ChatType(str, Enum):
    """Types of chats."""
    INDIVIDUAL = "individual"
    GROUP = "group"
    BROADCAST = "broadcast"
    STATUS = "status"
    NEWSLETTER = "newsletter"
    COMMUNITY = "community"

class ChatMessageType(str, Enum):
    """Types of messages in a chat."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    LOCATION = "location"
    CONTACT = "contact"
    STICKER = "sticker"
    REACTION = "reaction"
    SYSTEM = "system"
    UNKNOWN = "unknown"

class ChatState(str, Enum):
    """Chat state indicators."""
    COMPOSING = "composing"
    PAUSED = "paused"
    RECORDING = "recording"
    UPLOADING = "uploading"
    CANCEL = "cancel"

@dataclass
class Chat:
    """Represents a chat/conversation in WhatsApp."""
    jid: JID
    name: str
    type: ChatType = ChatType.INDIVIDUAL
    unread_count: int = 0
    is_marked_unread: bool = False
    is_read_only: bool = False
    is_archived: bool = False
    is_muted: bool = False
    is_pinned: bool = False
    mute_expiration: Optional[datetime] = None
    last_message_timestamp: Optional[datetime] = None
    last_message: Optional[Dict[str, Any]] = None
    last_message_sender: Optional[JID] = None
    last_message_status: Optional[str] = None
    last_message_receipt_timestamp: Optional[datetime] = None
    ephemeral_messages_ttl: Optional[int] = None
    ephemeral_setting_timestamp: Optional[datetime] = None
    participant_version: Optional[str] = None
    tc_token: Optional[bytes] = None
    tc_token_timestamp: Optional[datetime] = None
    tc_token_sender_timestamp: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if isinstance(self.jid, str):
            self.jid = JID.from_string(self.jid)
        if isinstance(self.last_message_sender, str):
            self.last_message_sender = JID.from_string(self.last_message_sender)
    
    @property
    def is_group(self) -> bool:
        """Check if this is a group chat."""
        return self.type == ChatType.GROUP or self.jid.is_group
    
    @property
    def is_broadcast(self) -> bool:
        """Check if this is a broadcast list."""
        return self.type == ChatType.BROADCAST
    
    @property
    def is_individual(self) -> bool:
        """Check if this is an individual chat."""
        return self.type == ChatType.INDIVIDUAL and not self.jid.is_group
    
    @property
    def is_status(self) -> bool:
        """Check if this is a status update chat."""
        return self.type == ChatType.STATUS
    
    @property
    def is_newsletter(self) -> bool:
        """Check if this is a newsletter chat."""
        return self.type == ChatType.NEWSLETTER
    
    @property
    def is_community(self) -> bool:
        """Check if this is a community chat."""
        return self.type == ChatType.COMMUNITY
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'jid': str(self.jid),
            'name': self.name,
            'type': self.type.value,
            'unread_count': self.unread_count,
            'is_marked_unread': self.is_marked_unread,
            'is_read_only': self.is_read_only,
            'is_archived': self.is_archived,
            'is_muted': self.is_muted,
            'is_pinned': self.is_pinned,
            'mute_expiration': self.mute_expiration.isoformat() if self.mute_expiration else None,
            'last_message_timestamp': self.last_message_timestamp.isoformat() if self.last_message_timestamp else None,
            'last_message': self.last_message,
            'last_message_sender': str(self.last_message_sender) if self.last_message_sender else None,
            'last_message_status': self.last_message_status,
            'last_message_receipt_timestamp': self.last_message_receipt_timestamp.isoformat() if self.last_message_receipt_timestamp else None,
            'ephemeral_messages_ttl': self.ephemeral_messages_ttl,
            'ephemeral_setting_timestamp': self.ephemeral_setting_timestamp.isoformat() if self.ephemeral_setting_timestamp else None,
            'participant_version': self.participant_version,
            'tc_token': self.tc_token.decode('latin-1') if self.tc_token else None,
            'tc_token_timestamp': self.tc_token_timestamp.isoformat() if self.tc_token_timestamp else None,
            'tc_token_sender_timestamp': self.tc_token_sender_timestamp.isoformat() if self.tc_token_sender_timestamp else None,
            'labels': self.labels,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Chat':
        """Create from a dictionary."""
        from datetime import datetime
        
        # Convert string timestamps back to datetime objects
        mute_expiration = (
            datetime.fromisoformat(data['mute_expiration'])
            if data.get('mute_expiration') else None
        )
        
        last_message_timestamp = (
            datetime.fromisoformat(data['last_message_timestamp'])
            if data.get('last_message_timestamp') else None
        )
        
        last_message_receipt_timestamp = (
            datetime.fromisoformat(data['last_message_receipt_timestamp'])
            if data.get('last_message_receipt_timestamp') else None
        )
        
        ephemeral_setting_timestamp = (
            datetime.fromisoformat(data['ephemeral_setting_timestamp'])
            if data.get('ephemeral_setting_timestamp') else None
        )
        
        tc_token_timestamp = (
            datetime.fromisoformat(data['tc_token_timestamp'])
            if data.get('tc_token_timestamp') else None
        )
        
        tc_token_sender_timestamp = (
            datetime.fromisoformat(data['tc_token_sender_timestamp'])
            if data.get('tc_token_sender_timestamp') else None
        )
        
        # Convert token string back to bytes if present
        tc_token = (
            data['tc_token'].encode('latin-1')
            if data.get('tc_token') else None
        )
        
        return cls(
            jid=data['jid'],
            name=data['name'],
            type=ChatType(data.get('type', 'individual')),
            unread_count=data.get('unread_count', 0),
            is_marked_unread=data.get('is_marked_unread', False),
            is_read_only=data.get('is_read_only', False),
            is_archived=data.get('is_archived', False),
            is_muted=data.get('is_muted', False),
            is_pinned=data.get('is_pinned', False),
            mute_expiration=mute_expiration,
            last_message_timestamp=last_message_timestamp,
            last_message=data.get('last_message'),
            last_message_sender=data.get('last_message_sender'),
            last_message_status=data.get('last_message_status'),
            last_message_receipt_timestamp=last_message_receipt_timestamp,
            ephemeral_messages_ttl=data.get('ephemeral_messages_ttl'),
            ephemeral_setting_timestamp=ephemeral_setting_timestamp,
            participant_version=data.get('participant_version'),
            tc_token=tc_token,
            tc_token_timestamp=tc_token_timestamp,
            tc_token_sender_timestamp=tc_token_sender_timestamp,
            labels=data.get('labels', []),
        )

@dataclass
class ChatEvent:
    """Represents an event in a chat."""
    id: str
    timestamp: datetime
    chat_jid: JID
    from_me: bool
    type: str
    data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'chat_jid': str(self.chat_jid),
            'from_me': self.from_me,
            'type': self.type,
            'data': self.data,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChatEvent':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            id=data['id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            chat_jid=JID.from_string(data['chat_jid']),
            from_me=data['from_me'],
            type=data['type'],
            data=data['data'],
        )

@dataclass
class ChatPresence:
    """Represents a user's presence in a chat."""
    chat_jid: JID
    user_jid: JID
    state: str
    last_seen: Optional[datetime] = None
    last_known_presence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'chat_jid': str(self.chat_jid),
            'user_jid': str(self.user_jid),
            'state': self.state,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'last_known_presence': self.last_known_presence,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChatPresence':
        """Create from a dictionary."""
        from datetime import datetime
        last_seen = (
            datetime.fromisoformat(data['last_seen'])
            if data.get('last_seen') else None
        )
        return cls(
            chat_jid=JID.from_string(data['chat_jid']),
            user_jid=JID.from_string(data['user_jid']),
            state=data['state'],
            last_seen=last_seen,
            last_known_presence=data.get('last_known_presence'),
        )

# For backward compatibility
ChatInfo = Chat
