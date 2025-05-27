from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Optional


class Presence(str, Enum):
    """User presence status."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class ChatPresence(str, Enum):
    """Chat presence/typing status."""
    COMPOSING = "composing"
    PAUSED = "paused"


class ChatPresenceMedia(str, Enum):
    """Media type for chat presence (e.g., when recording audio)."""
    TEXT = ""
    AUDIO = "audio"


@dataclass
class PresenceEvent:
    """Event emitted when a user's presence changes.
    
    Attributes:
        from_jid: The JID of the user whose presence changed
        unavailable: Whether the user is now unavailable/offline
        last_seen: When the user was last seen online (if available)
    """
    from_jid: str
    unavailable: bool
    last_seen: Optional[datetime] = None


@dataclass
class ChatPresenceEvent:
    """Event emitted when a user's chat presence changes (e.g., typing).
    
    Attributes:
        from_jid: The JID of the user
        to_jid: The JID of the chat
        state: The new chat presence state
        media: The type of media being composed (if any)
    """
    from_jid: str
    to_jid: str
    state: ChatPresence
    media: ChatPresenceMedia = ChatPresenceMedia.TEXT
