"""
Message reaction types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any

from .jid import JID

class ReactionAction(str, Enum):
    """Types of reaction actions."""
    ADD = "add"
    REMOVE = "remove"
    MODIFY = "modify"

@dataclass
class ReactionInfo:
    """Information about a reaction to a message."""
    message_id: str
    sender_jid: JID
    reaction_text: str  # Emoji or text used as reaction
    timestamp: datetime
    action: ReactionAction = ReactionAction.ADD
    is_removed: bool = False
    reaction_count: int = 1  # For aggregated reactions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'sender_jid': str(self.sender_jid),
            'reaction_text': self.reaction_text,
            'timestamp': self.timestamp.isoformat(),
            'action': self.action.value,
            'is_removed': self.is_removed,
            'reaction_count': self.reaction_count,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReactionInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            sender_jid=JID.from_string(data['sender_jid']),
            reaction_text=data['reaction_text'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            action=ReactionAction(data.get('action', 'add')),
            is_removed=data.get('is_removed', False),
            reaction_count=data.get('reaction_count', 1),
        )

@dataclass
class ReactionAggregation:
    """Aggregated reaction information for a message."""
    message_id: str
    chat_jid: JID
    reactions: Dict[str, int]  # reaction_text -> count
    user_reactions: Dict[str, List[JID]]  # reaction_text -> list of user JIDs
    last_updated: datetime
    
    def get_reaction_count(self, reaction_text: str) -> int:
        """Get the count for a specific reaction."""
        return self.reactions.get(reaction_text, 0)
    
    def get_users_for_reaction(self, reaction_text: str) -> List[JID]:
        """Get the list of users who reacted with a specific reaction."""
        return self.user_reactions.get(reaction_text, [])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'chat_jid': str(self.chat_jid),
            'reactions': self.reactions,
            'user_reactions': {k: [str(jid) for jid in v] for k, v in self.user_reactions.items()},
            'last_updated': self.last_updated.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReactionAggregation':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            chat_jid=JID.from_string(data['chat_jid']),
            reactions=data.get('reactions', {}),
            user_reactions={
                k: [JID.from_string(jid_str) for jid_str in v] 
                for k, v in data.get('user_reactions', {}).items()
            },
            last_updated=datetime.fromisoformat(data['last_updated']),
        )

@dataclass
class ReactionSync:
    """Synchronization information for reactions."""
    message_id: str
    chat_jid: JID
    from_me: bool
    reaction_info: ReactionInfo
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'message_id': self.message_id,
            'chat_jid': str(self.chat_jid),
            'from_me': self.from_me,
            'reaction_info': self.reaction_info.to_dict(),
            'timestamp': self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReactionSync':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_id=data['message_id'],
            chat_jid=JID.from_string(data['chat_jid']),
            from_me=data['from_me'],
            reaction_info=ReactionInfo.from_dict(data['reaction_info']),
            timestamp=datetime.fromisoformat(data['timestamp']),
        )

@dataclass
class ReactionSettings:
    """Settings for message reactions."""
    is_enabled: bool = True
    allow_all_emojis: bool = True
    allowed_emojis: List[str] = field(default_factory=list)
    max_reactions_per_message: int = 20
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'is_enabled': self.is_enabled,
            'allow_all_emojis': self.allow_all_emojis,
            'allowed_emojis': self.allowed_emojis,
            'max_reactions_per_message': self.max_reactions_per_message,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReactionSettings':
        """Create from a dictionary."""
        return cls(
            is_enabled=data.get('is_enabled', True),
            allow_all_emojis=data.get('allow_all_emojis', True),
            allowed_emojis=data.get('allowed_emojis', []),
            max_reactions_per_message=data.get('max_reactions_per_message', 20),
        )
