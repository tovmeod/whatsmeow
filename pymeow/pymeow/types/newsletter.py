"""
Newsletter types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Union

from .jid import JID


class NewsletterState(str, Enum):
    """Possible states of a newsletter."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class NewsletterRole(str, Enum):
    """Roles that a user can have in a newsletter."""
    OWNER = "owner"
    ADMIN = "admin"
    SUBSCRIBER = "subscriber"
    GUEST = "guest"


class NewsletterMuteState(str, Enum):
    """Mute states for a newsletter."""
    MUTED = "muted"
    UNMUTED = "unmuted"


class NewsletterReactionsMode(str, Enum):
    """Reaction modes for newsletters."""
    ALL = "all"
    NONE = "none"
    FOLLOWERS = "followers"


class NewsletterVerificationStatus(str, Enum):
    """Verification status of a newsletter."""
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    IN_REVIEW = "in_review"
    REJECTED = "rejected"


@dataclass
class NewsletterSettings:
    """Settings for a newsletter."""
    name: str
    description: str = ""
    is_muted: bool = False
    is_following: bool = False
    is_subscribed: bool = False
    is_admin: bool = False
    is_verified: bool = False
    verification_status: NewsletterVerificationStatus = NewsletterVerificationStatus.UNVERIFIED
    reactions_mode: NewsletterReactionsMode = NewsletterReactionsMode.ALL
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'name': self.name,
            'description': self.description,
            'is_muted': self.is_muted,
            'is_following': self.is_following,
            'is_subscribed': self.is_subscribed,
            'is_admin': self.is_admin,
            'is_verified': self.is_verified,
            'verification_status': self.verification_status.value,
            'reactions_mode': self.reactions_mode.value,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'NewsletterSettings':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            name=data['name'],
            description=data.get('description', ''),
            is_muted=data.get('is_muted', False),
            is_following=data.get('is_following', False),
            is_subscribed=data.get('is_subscribed', False),
            is_admin=data.get('is_admin', False),
            is_verified=data.get('is_verified', False),
            verification_status=NewsletterVerificationStatus(data.get('verification_status', 'unverified')),
            reactions_mode=NewsletterReactionsMode(data.get('reactions_mode', 'all')),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None,
        )


@dataclass
class NewsletterMessageInfo:
    """Information about a newsletter message."""
    message_id: str
    newsletter_jid: JID
    author_jid: JID
    timestamp: datetime
    content: str
    
    # Message status
    is_edited: bool = False
    is_deleted: bool = False
    is_forwarded: bool = False
    
    # Engagement metrics
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    
    # Media information
    has_media: bool = False
    media_url: Optional[str] = None
    media_type: Optional[str] = None
    media_caption: Optional[str] = None
    
    # Additional metadata
    raw_data: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'newsletter_jid': str(self.newsletter_jid),
            'author_jid': str(self.author_jid),
            'timestamp': self.timestamp.isoformat(),
            'content': self.content,
            'is_edited': self.is_edited,
            'is_deleted': self.is_deleted,
            'is_forwarded': self.is_forwarded,
            'view_count': self.view_count,
            'like_count': self.like_count,
            'comment_count': self.comment_count,
            'has_media': self.has_media,
            'media_url': self.media_url,
            'media_type': self.media_type,
            'media_caption': self.media_caption,
            'raw_data': self.raw_data,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'NewsletterMessageInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            newsletter_jid=JID.from_string(data['newsletter_jid']),
            author_jid=JID.from_string(data['author_jid']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            content=data['content'],
            is_edited=data.get('is_edited', False),
            is_deleted=data.get('is_deleted', False),
            is_forwarded=data.get('is_forwarded', False),
            view_count=data.get('view_count', 0),
            like_count=data.get('like_count', 0),
            comment_count=data.get('comment_count', 0),
            has_media=data.get('has_media', False),
            media_url=data.get('media_url'),
            media_type=data.get('media_type'),
            media_caption=data.get('media_caption'),
            raw_data=data.get('raw_data'),
        )


@dataclass
class NewsletterReaction:
    """A reaction to a newsletter message."""
    message_id: str
    newsletter_jid: JID
    reactor_jid: JID
    reaction: str
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'newsletter_jid': str(self.newsletter_jid),
            'reactor_jid': str(self.reactor_jid),
            'reaction': self.reaction,
            'timestamp': self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'NewsletterReaction':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            newsletter_jid=JID.from_string(data['newsletter_jid']),
            reactor_jid=JID.from_string(data['reactor_jid']),
            reaction=data['reaction'],
            timestamp=datetime.fromisoformat(data['timestamp']),
        )
