"""
Message receipt events.

Port of whatsmeow/types/events/message.go
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

@dataclass
class MessageReceipt:
    """Receipt event for a message."""
    chat_jid: str
    message_ids: List[str]
    timestamp: datetime

@dataclass
class ReceiptType:
    """Types of message receipts."""
    READ = "read"
    READ_SELF = "read-self"
    DELIVERED = "delivered"
    PLAYED = "played"

@dataclass
class GroupNotification:
    """Group-related notification event."""
    jid: str
    actor: Optional[str]
    timestamp: datetime
    type: str  # join, leave, etc
    participants: List[str]
