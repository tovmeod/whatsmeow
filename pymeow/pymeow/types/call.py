"""
Call-related types for PyMeow.

Port of whatsmeow/types/call.go
"""
from dataclasses import dataclass
from datetime import datetime

from .jid import JID


@dataclass
class BasicCallMeta:
    """Basic metadata about a call."""
    from_jid: JID
    timestamp: datetime
    call_creator: JID
    call_id: str


@dataclass
class CallRemoteMeta:
    """Information about the remote caller's WhatsApp client."""
    remote_platform: str  # The platform of the caller's WhatsApp client
    remote_version: str  # Version of the caller's WhatsApp client
