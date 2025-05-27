"""
Presence handling for WhatsApp.

Port of whatsmeow/presence.go
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

from .types.events import Message

class PresenceType:
    """Types of presence states."""
    UNAVAILABLE = "unavailable"
    AVAILABLE = "available"
    COMPOSING = "composing"
    RECORDING = "recording"
    PAUSED = "paused"

@dataclass
class Presence:
    """User presence information."""
    user_jid: str
    timestamp: datetime
    state: str

class PresenceManager:
    """Manages user presence states."""

    def __init__(self):
        self._states: Dict[str, Presence] = {}

    def handle_presence(self, presence: Presence) -> None:
        """Handle an incoming presence update."""
        self._states[presence.user_jid] = presence

    def get_presence(self, user_jid: str) -> Optional[Presence]:
        """Get the current presence state for a user."""
        return self._states.get(user_jid)
