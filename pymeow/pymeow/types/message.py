"""
Message-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Tuple, Set

from .jid import JID
from .expiration import ExpirationInfo, ExpirationType


class MessageType(Enum):
    """Types of messages."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    STICKER = "sticker"
    LOCATION = "location"
    CONTACT = "contact"
    CONTACTS = "contacts"
    GROUP_INVITE = "group_invite"
    LIST = "list"
    BUTTONS = "buttons"
    TEMPLATE = "template"
    REACTION = "reaction"
    POLL_CREATE = "poll_creation"
    POLL_VOTE = "poll_vote"
    UNKNOWN = "unknown"


class MessageStatus(Enum):
    """Status of a message."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class MessageKey:
    """Unique identifier for a message."""
    id: str
    remote_jid: JID
    from_me: bool
    participant: Optional[JID] = None
    owner_jid: Optional[JID] = None
    
    def __post_init__(self):
        if isinstance(self.remote_jid, str):
            self.remote_jid = JID.from_string(self.remote_jid)
        if self.participant and isinstance(self.participant, str):
            self.participant = JID.from_string(self.participant)
        if self.owner_jid and isinstance(self.owner_jid, str):
            self.owner_jid = JID.from_string(self.owner_jid)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'remoteJid': str(self.remote_jid),
            'fromMe': self.from_me,
            'participant': str(self.participant) if self.participant else None,
            'ownerJid': str(self.owner_jid) if self.owner_jid else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageKey':
        return cls(
            id=data.get('id', ''),
            remote_jid=data.get('remoteJid', ''),
            from_me=data.get('fromMe', False),
            participant=data.get('participant'),
            owner_jid=data.get('ownerJid')
        )


@dataclass
class MessageInfo:
    """Metadata about a message."""
    key: MessageKey
    message_timestamp: int
    message_sequence_number: int = 0
    push_name: str = ""
    status: MessageStatus = MessageStatus.PENDING
    message_context_info: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def id(self) -> str:
        """Get the message ID."""
        return self.key.id
    
    @property
    def from_me(self) -> bool:
        """Check if the message was sent by the current user."""
        return self.key.from_me
    
    @property
    def remote_jid(self) -> JID:
        """Get the JID of the chat the message belongs to."""
        return self.key.remote_jid
    
    @property
    def participant(self) -> Optional[JID]:
        """Get the participant JID if this is a group message."""
        return self.key.participant
    
    @property
    def timestamp(self) -> datetime:
        """Get the message timestamp as a datetime object."""
        return datetime.fromtimestamp(self.message_timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'key': self.key.to_dict(),
            'messageTimestamp': self.message_timestamp,
            'messageSequenceNumber': self.message_sequence_number,
            'pushName': self.push_name,
            'status': self.status.value,
            'messageContextInfo': self.message_context_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageInfo':
        """Create from a dictionary."""
        return cls(
            key=MessageKey.from_dict(data.get('key', {})),
            message_timestamp=data.get('messageTimestamp', 0),
            message_sequence_number=data.get('messageSequenceNumber', 0),
            push_name=data.get('pushName', ''),
            status=MessageStatus(data.get('status', 'pending')),
            message_context_info=data.get('messageContextInfo', {})
        )


@dataclass
class Message:
    """A WhatsApp message."""
    info: MessageInfo
    message: Dict[str, Any]
    message_type: MessageType = MessageType.UNKNOWN
    expiration_info: Optional[ExpirationInfo] = None
    is_ephemeral: bool = False
    
    @property
    def id(self) -> str:
        """Get the message ID."""
        return self.info.id
    
    @property
    def from_me(self) -> bool:
        """Check if the message was sent by the current user."""
        return self.info.from_me
    
    @property
    def remote_jid(self) -> JID:
        """Get the JID of the chat the message belongs to."""
        return self.info.remote_jid
    
    @property
    def timestamp(self) -> datetime:
        """Get the message timestamp as a datetime object."""
        return self.info.timestamp
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        result = {
            'info': self.info.to_dict(),
            'message': self.message,
            'messageType': self.message_type.value,
            'is_ephemeral': self.is_ephemeral
        }
        if self.expiration_info:
            result['expiration_info'] = self.expiration_info.to_dict()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create from a dictionary."""
        expiration_info_data = data.get('expiration_info')
        expiration_info = ExpirationInfo.from_dict(expiration_info_data) if expiration_info_data else None
        
        return cls(
            info=MessageInfo.from_dict(data.get('info', {})),
            message=data.get('message', {}),
            message_type=MessageType(data.get('messageType', 'unknown')),
            expiration_info=expiration_info,
            is_ephemeral=data.get('is_ephemeral', False)
        )
