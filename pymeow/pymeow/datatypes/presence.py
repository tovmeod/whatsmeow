"""
WhatsApp presence types.

Port of whatsmeow/types/presence.go

This file contains both the enum types from the Go implementation and additional
dataclasses (PresenceEvent and ChatPresenceEvent) that are used for convenience
in the Python implementation. These dataclasses are also defined in events.py
for compatibility with the Go implementation's event system, but are included here
for direct use when working with presence-related functionality.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
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


class ReceiptType(str, Enum):
    """Type of receipt event."""
    # Message was delivered to the device (but the user might not have noticed)
    DELIVERED = ""
    # Sent by your other devices when a message you sent is delivered to them
    SENDER = "sender"
    # Message was delivered to the device, but decrypting the message failed
    RETRY = "retry"
    # User opened the chat and saw the message
    READ = "read"
    # Current user read a message from a different device, and has read receipts disabled in privacy settings
    READ_SELF = "read-self"
    # User opened a view-once media message
    PLAYED = "played"
    # Current user opened a view-once media message from a different device, and has read receipts disabled in privacy settings
    PLAYED_SELF = "played-self"
    # Server error
    SERVER_ERROR = "server-error"
    # Inactive
    INACTIVE = "inactive"
    # Peer message
    PEER_MSG = "peer_msg"
    # History sync
    HISTORY_SYNC = "hist_sync"

    def __repr__(self) -> str:
        """Return a string representation of the receipt type."""
        if self == ReceiptType.READ:
            return "ReceiptType.READ"
        elif self == ReceiptType.READ_SELF:
            return "ReceiptType.READ_SELF"
        elif self == ReceiptType.DELIVERED:
            return "ReceiptType.DELIVERED"
        elif self == ReceiptType.PLAYED:
            return "ReceiptType.PLAYED"
        else:
            return f"ReceiptType({repr(self.value)})"


@dataclass
class PresenceEvent:
    """Event emitted when a user's presence changes.

    This dataclass is included in presence.py (in addition to events.py) to provide
    direct access to presence-related event structures without requiring imports from events.py.
    This allows for more intuitive code organization when working with presence functionality.

    Example usage:
        # Creating a presence event
        event = PresenceEvent(
            from_jid="user@whatsapp.net",
            unavailable=False
        )

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

    This dataclass is included in presence.py (in addition to events.py) to provide
    direct access to chat presence-related event structures without requiring imports from events.py.
    This allows for more intuitive code organization when working with chat presence functionality.

    Example usage:
        # Creating a chat presence event
        event = ChatPresenceEvent(
            from_jid="user@whatsapp.net",
            to_jid="chat@whatsapp.net",
            state=ChatPresence.COMPOSING,
            media=ChatPresenceMedia.TEXT
        )

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
