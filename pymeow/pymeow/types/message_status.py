"""
Message status types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union

from .jid import JID


class MessageStatusType(str, Enum):
    """Types of message status updates."""
    DELIVERED = "delivered"
    READ = "read"
    PLAYED = "played"  # For view-once messages
    FAILED = "failed"
    PENDING = "pending"
    SERVER_ACK = "server_ack"
    SENDER_REVOKE = "sender_revoke"  # When sender deletes for everyone
    RECIPIENT_REVOKE = "recipient_revoke"  # When recipient deletes for everyone


class MessageStatusError(str, Enum):
    """Possible error states for failed message delivery."""
    UNKNOWN = "unknown"
    OFFLINE = "offline"
    TIMEOUT = "timeout"
    REJECTED = "rejected"
    INTERNAL = "internal"
    SERVER = "server"
    UNAVAILABLE = "unavailable"
    BLOCKED = "blocked"
    NOT_AUTHORIZED = "not_authorized"
    MEDIA_UPLOAD = "media_upload"
    MEDIA_DOWNLOAD = "media_download"


@dataclass
class MessageStatusInfo:
    """Information about a message status update."""
    message_id: str
    from_me: bool
    status: MessageStatusType
    timestamp: datetime
    
    # For failed messages
    error: Optional[MessageStatusError] = None
    error_text: Optional[str] = None
    
    # For read/delivered receipts
    participant: Optional[JID] = None  # For group messages
    
    # Additional metadata
    offline: bool = False  # If the status was received while offline
    is_latest: bool = True  # If this is the most recent status for the message
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'from_me': self.from_me,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat(),
            'error': self.error.value if self.error else None,
            'error_text': self.error_text,
            'participant': str(self.participant) if self.participant else None,
            'offline': self.offline,
            'is_latest': self.is_latest,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MessageStatusInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            from_me=data['from_me'],
            status=MessageStatusType(data['status']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            error=MessageStatusError(data['error']) if data.get('error') else None,
            error_text=data.get('error_text'),
            participant=JID.from_string(data['participant']) if data.get('participant') else None,
            offline=data.get('offline', False),
            is_latest=data.get('is_latest', True),
        )


@dataclass
class MessageStatusUpdate:
    """A batch of message status updates."""
    updates: List[MessageStatusInfo]
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'updates': [update.to_dict() for update in self.updates],
            'timestamp': self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'MessageStatusUpdate':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            updates=[MessageStatusInfo.from_dict(update) for update in data['updates']],
            timestamp=datetime.fromisoformat(data['timestamp']),
        )
