"""
Receipt types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Set

from .jid import JID


class ReceiptType(str, Enum):
    """Types of message receipts."""
    DELIVERED = "delivered"  # Message was delivered to the device
    READ = "read"           # Message was read by the recipient
    PLAYED = "played"        # Audio/video message was played
    SERVER = "server"        # Server acknowledgment
    SENDER = "sender"        # Sender acknowledgment
    RETRY = "retry"          # Retry receipt
    INACTIVE = "inactive"    # Inactive receipt (user was inactive)
    PEER_MSG = "peer_msg"    # Peer message receipt
    HISTORY_SYNC = "history_sync"  # History sync receipt


@dataclass
class ReceiptInfo:
    """Information about a message receipt."""
    message_ids: List[str]  # The message IDs this receipt is for
    receipt_type: ReceiptType
    timestamp: datetime
    
    # The recipient of the receipt (who sent the receipt)
    recipient_jid: JID
    
    # For group messages
    participant: Optional[JID] = None
    
    # For read receipts, the count of unread messages
    unread_messages: Optional[int] = None
    
    # Additional metadata
    offline: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'message_ids': self.message_ids,
            'receipt_type': self.receipt_type.value,
            'timestamp': self.timestamp.isoformat(),
            'recipient_jid': str(self.recipient_jid),
            'participant': str(self.participant) if self.participant else None,
            'unread_messages': self.unread_messages,
            'offline': self.offline,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ReceiptInfo':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            message_ids=data['message_ids'],
            receipt_type=ReceiptType(data['receipt_type']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            recipient_jid=JID.from_string(data['recipient_jid']),
            participant=JID.from_string(data['participant']) if data.get('participant') else None,
            unread_messages=data.get('unread_messages'),
            offline=data.get('offline', False),
        )


@dataclass
class ReceiptBatch:
    """A batch of message receipts."""
    receipts: List[ReceiptInfo]
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'receipts': [receipt.to_dict() for receipt in self.receipts],
            'timestamp': self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ReceiptBatch':
        """Create from a dictionary."""
        from datetime import datetime
        return cls(
            receipts=[ReceiptInfo.from_dict(receipt) for receipt in data['receipts']],
            timestamp=datetime.fromisoformat(data['timestamp']),
        )


@dataclass
class ReadReceiptRequest:
    """A request for read receipts."""
    message_ids: List[str]
    chat_jid: JID
    sender_jid: JID
    
    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'message_ids': self.message_ids,
            'chat_jid': str(self.chat_jid),
            'sender_jid': str(self.sender_jid),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ReadReceiptRequest':
        """Create from a dictionary."""
        return cls(
            message_ids=data['message_ids'],
            chat_jid=JID.from_string(data['chat_jid']),
            sender_jid=JID.from_string(data['sender_jid']),
        )
