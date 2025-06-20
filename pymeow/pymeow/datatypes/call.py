"""
Call-related types for WhatsApp.

Port of whatsmeow/types/call.go
"""

from dataclasses import dataclass
from datetime import datetime

from .jid import JID


@dataclass
class BasicCallMeta:
    """Basic metadata for call events."""
    from_jid: JID
    timestamp: datetime
    call_creator: JID
    call_id: str


@dataclass
class CallRemoteMeta:
    """Remote platform metadata for call events."""
    remote_platform: str
    remote_version: str
