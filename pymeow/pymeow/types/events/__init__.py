"""
WhatsApp events interface.

Port of whatsmeow/types/events/
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List

from ...generated.waMsgTransport import WAMsgTransport_pb2
from ..message import MessageSource

@dataclass
class QR:
    """Event for when a QR code should be displayed for pairing."""
    code: bytes

@dataclass
class Connected:
    """Event for when the connection to WhatsApp is established."""
    pass

@dataclass
class LoggedOut:
    """Event for when the client is logged out."""
    pass

@dataclass
class Message:
    """Event for when a message is received."""
    message: WAMsgTransport_pb2.Message
    source: MessageSource

@dataclass
class Receipt:
    """Event for message receipt updates."""
    message_id: str
    sender: str
    timestamp: datetime
    type: str  # read, delivery, etc
