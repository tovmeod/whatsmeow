"""
Status and story-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any, Tuple

from .jid import JID
from .media import MediaInfo, MediaType

class StatusType(str, Enum):
    """Types of status updates."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    UNKNOWN = "unknown"

class StatusPrivacy(str, Enum):
    """Privacy settings for status updates."""
    ALL = "all"
    MY_CONTACTS = "contacts"
    MY_CONTACTS_EXCEPT = "contacts_except"
    SHARE = "share"
    HIDE = "hide"
    WHITELIST = "whitelist"

@dataclass
class StatusInfo:
    """Information about a status update."""
    status_id: str
    owner_jid: JID
    status_type: StatusType
    timestamp: datetime
    caption: Optional[str] = None
    media_info: Optional[MediaInfo] = None
    duration: Optional[float] = None  # in seconds
    is_viewed: bool = False
    is_mine: bool = False
    privacy: StatusPrivacy = StatusPrivacy.MY_CONTACTS
    allowed_viewers: List[JID] = field(default_factory=list)
    expiration: Optional[datetime] = None  # When the status will expire
    
    def __post_init__(self):
        if self.expiration is None and self.status_type != StatusType.TEXT:
            # Default expiration: 24 hours from timestamp for media statuses
            self.expiration = self.timestamp + timedelta(hours=24)
    
    @property
    def is_expired(self) -> bool:
        """Check if the status has expired."""
        if self.expiration is None:
            return False
        return datetime.now() > self.expiration
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'status_id': self.status_id,
            'owner_jid': str(self.owner_jid),
            'status_type': self.status_type.value,
            'timestamp': self.timestamp.isoformat(),
            'caption': self.caption,
            'media_info': self.media_info.to_dict() if self.media_info else None,
            'duration': self.duration,
            'is_viewed': self.is_viewed,
            'is_mine': self.is_mine,
            'privacy': self.privacy.value,
            'allowed_viewers': [str(jid) for jid in self.allowed_viewers],
            'expiration': self.expiration.isoformat() if self.expiration else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StatusInfo':
        """Create from a dictionary."""
        from datetime import datetime
        from .media import MediaInfo
        
        media_info_data = data.get('media_info')
        media_info = MediaInfo.from_dict(media_info_data) if media_info_data else None
        
        return cls(
            status_id=data['status_id'],
            owner_jid=JID.from_string(data['owner_jid']),
            status_type=StatusType(data['status_type']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            caption=data.get('caption'),
            media_info=media_info,
            duration=data.get('duration'),
            is_viewed=data.get('is_viewed', False),
            is_mine=data.get('is_mine', False),
            privacy=StatusPrivacy(data.get('privacy', 'contacts')),
            allowed_viewers=[JID.from_string(jid_str) for jid_str in data.get('allowed_viewers', [])],
            expiration=datetime.fromisoformat(data['expiration']) if data.get('expiration') else None,
        )

@dataclass
class StatusViewerInfo:
    """Information about who has viewed a status."""
    status_id: str
    viewer_jid: JID
    timestamp: datetime
    is_muted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'status_id': self.status_id,
            'viewer_jid': str(self.viewer_jid),
            'timestamp': self.timestamp.isoformat(),
            'is_muted': self.is_muted,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StatusViewerInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            status_id=data['status_id'],
            viewer_jid=JID.from_string(data['viewer_jid']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            is_muted=data.get('is_muted', False),
        )

@dataclass
class StatusPrivacySettings:
    """Privacy settings for status updates."""
    default_status_privacy: StatusPrivacy = StatusPrivacy.MY_CONTACTS
    blocked_viewers: List[JID] = field(default_factory=list)
    allowed_viewers: List[JID] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'default_status_privacy': self.default_status_privacy.value,
            'blocked_viewers': [str(jid) for jid in self.blocked_viewers],
            'allowed_viewers': [str(jid) for jid in self.allowed_viewers],
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StatusPrivacySettings':
        """Create from a dictionary."""
        return cls(
            default_status_privacy=StatusPrivacy(data.get('default_status_privacy', 'contacts')),
            blocked_viewers=[JID.from_string(jid_str) for jid_str in data.get('blocked_viewers', [])],
            allowed_viewers=[JID.from_string(jid_str) for jid_str in data.get('allowed_viewers', [])],
        )

@dataclass
class StoryReplyInfo:
    """Information about a reply to a story."""
    story_id: str
    reply_id: str
    sender_jid: JID
    text: str
    timestamp: datetime
    is_forwarded: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'story_id': self.story_id,
            'reply_id': self.reply_id,
            'sender_jid': str(self.sender_jid),
            'text': self.text,
            'timestamp': self.timestamp.isoformat(),
            'is_forwarded': self.is_forwarded,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StoryReplyInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            story_id=data['story_id'],
            reply_id=data['reply_id'],
            sender_jid=JID.from_string(data['sender_jid']),
            text=data['text'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            is_forwarded=data.get('is_forwarded', False),
        )
