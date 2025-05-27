"""
Message types for WhatsApp.

Port of whatsmeow/types/message.go
"""
from datetime import datetime
from typing import Optional, Dict, List, Any, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum, auto

from ..generated.waMsgTransport import WAMsgTransport_pb2

if TYPE_CHECKING:
    from .contact import Contact
    from .reaction import Reaction

class MessageType(Enum):
    """Types of WhatsApp messages."""
    TEXT = auto()
    IMAGE = auto()
    VIDEO = auto()
    AUDIO = auto()
    DOCUMENT = auto()
    STICKER = auto()
    LOCATION = auto()
    CONTACT = auto()
    CONTACT_ARRAY = auto()
    REACTION = auto()
    UNKNOWN = auto()

class MessageStatus(Enum):
    """Status of a WhatsApp message."""
    PENDING = auto()
    SERVER_ACK = auto()
    DELIVERY_ACK = auto()
    READ = auto()
    PLAYED = auto()
    ERROR = auto()

@dataclass
class MessageSource:
    """Contains basic sender and chat information about a message."""
    chat: str  # The chat where the message was sent
    sender: str  # The user who sent the message
    is_from_me: bool  # Whether the message was sent by the current user
    is_group: bool  # Whether the chat is a group chat or broadcast list

@dataclass
class Message:
    """Represents a WhatsApp message."""
    id: str
    timestamp: datetime
    from_me: bool
    chat_id: str
    sender_id: str
    message_type: 'MessageType'
    content: Any
    status: 'MessageStatus' = MessageStatus.PENDING
    quoted_message: Optional['Message'] = None
    mentions: List[str] = field(default_factory=list)
    media_url: Optional[str] = None
    media_caption: Optional[str] = None
    media_mimetype: Optional[str] = None
    media_sha256: Optional[bytes] = None
    media_file_length: Optional[int] = None
    media_file_name: Optional[str] = None
    location: Optional[Dict[str, float]] = None
    contact: Optional['Contact'] = None
    contacts: List['Contact'] = field(default_factory=list)
    is_forwarded: bool = False
    is_ephemeral: bool = False
    is_view_once: bool = False
    is_from_template: bool = False
    template_params: List[Dict[str, Any]] = field(default_factory=list)
    poll_name: Optional[str] = None
    poll_options: List[Dict[str, Any]] = field(default_factory=list)
    poll_selectable_options_count: Optional[int] = None
    poll_invalidated: bool = False
    poll_votes: List[Dict[str, Any]] = field(default_factory=list)
    reactions: List['Reaction'] = field(default_factory=list)
    reaction_to: Optional[str] = None  # For reaction messages, the ID of the message being reacted to


@dataclass
class MessageKey:
    """Represents a unique key for a message.
    
    This is used to identify messages across the system.
    """
    remote_jid: str
    from_me: bool
    id: str
    participant: Optional[str] = None  # For group messages, the sender JID
    
    def __str__(self) -> str:
        return f"{self.remote_jid}/{'me' if self.from_me else 'them'}/{self.id}"


@dataclass
class MessageInfo:
    """Contains metadata about a message.
    
    This is used to track message delivery status and other metadata.
    """
    key: MessageKey
    message: Optional[Message] = None
    timestamp: Optional[datetime] = None
    status: Optional[MessageStatus] = None
    participant: Optional[str] = None  # For group messages, the sender JID
    push_name: Optional[str] = None
    broadcast: bool = False
    category: Optional[str] = None
    is_forwarded: bool = False
    is_ephemeral: bool = False
    is_view_once: bool = False
    is_from_template: bool = False
    is_edited: bool = False
    is_deleted: bool = False
    is_media_uploaded: bool = False
    media_key: Optional[bytes] = None
    media_duration: Optional[int] = None
    media_caption: Optional[str] = None
    media_file_name: Optional[str] = None
    media_file_length: Optional[int] = None
    media_mime_type: Optional[str] = None
    media_sha256: Optional[bytes] = None
    media_enc_sha256: Optional[bytes] = None
    media_direct_path: Optional[str] = None
    media_url: Optional[str] = None
    media_size: Optional[int] = None
    media_height: Optional[int] = None
    media_width: Optional[int] = None
    media_caption_pending: bool = False
    media_caption_missing: bool = False
    media_retry_after: Optional[int] = None
    media_retry_count: int = 0
    media_retry_error: Optional[str] = None
    media_retry_error_code: Optional[int] = None
    media_retry_error_http_code: Optional[int] = None
    media_retry_error_http_status: Optional[str] = None
    media_retry_error_http_headers: Optional[Dict[str, str]] = None
    media_retry_error_http_body: Optional[bytes] = None
    media_retry_error_http_url: Optional[str] = None
    media_retry_error_http_method: Optional[str] = None
    media_retry_error_http_response: Optional[bytes] = None
    media_retry_error_http_status_code: Optional[int] = None
    media_retry_error_http_status_text: Optional[str] = None
    media_retry_error_http_headers_str: Optional[str] = None
    media_retry_error_http_body_str: Optional[str] = None
    media_retry_error_http_response_str: Optional[str] = None
    media_retry_error_http_headers_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_list: Optional[List[Dict[str, str]]] = None
    media_retry_error_http_headers_tuple: Optional[tuple] = None
    media_retry_error_http_headers_set: Optional[set] = None
    media_retry_error_http_headers_frozenset: Optional[frozenset] = None
    media_retry_error_http_headers_ordered_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_default_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_chain_map: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_counter: Optional[Dict[str, int]] = None
    media_retry_error_http_headers_deque: Optional[list] = None
    media_retry_error_http_headers_dict_items: Optional[list] = None
    media_retry_error_http_headers_dict_keys: Optional[list] = None
    media_retry_error_http_headers_dict_values: Optional[list] = None
    media_retry_error_http_headers_dict_items_view: Optional[list] = None
    media_retry_error_http_headers_dict_keys_view: Optional[list] = None
    media_retry_error_http_headers_dict_values_view: Optional[list] = None
    media_retry_error_http_headers_dict_items_list: Optional[list] = None
    media_retry_error_http_headers_dict_keys_list: Optional[list] = None
    media_retry_error_http_headers_dict_values_list: Optional[list] = None
    media_retry_error_http_headers_dict_items_set: Optional[set] = None
    media_retry_error_http_headers_dict_keys_set: Optional[set] = None
    media_retry_error_http_headers_dict_values_set: Optional[set] = None
    media_retry_error_http_headers_dict_items_frozenset: Optional[frozenset] = None
    media_retry_error_http_headers_dict_keys_frozenset: Optional[frozenset] = None
    media_retry_error_http_headers_dict_values_frozenset: Optional[frozenset] = None
    media_retry_error_http_headers_dict_items_tuple: Optional[tuple] = None
    media_retry_error_http_headers_dict_keys_tuple: Optional[tuple] = None
    media_retry_error_http_headers_dict_values_tuple: Optional[tuple] = None
    media_retry_error_http_headers_dict_items_ordered_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_keys_ordered_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_values_ordered_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_items_default_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_keys_default_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_values_default_dict: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_items_chain_map: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_keys_chain_map: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_values_chain_map: Optional[Dict[str, str]] = None
    media_retry_error_http_headers_dict_items_counter: Optional[Dict[str, int]] = None
    media_retry_error_http_headers_dict_keys_counter: Optional[Dict[str, int]] = None
    media_retry_error_http_headers_dict_values_counter: Optional[Dict[str, int]] = None
    media_retry_error_http_headers_dict_items_deque: Optional[list] = None
    media_retry_error_http_headers_dict_keys_deque: Optional[list] = None
    media_retry_error_http_headers_dict_values_deque: Optional[list] = None
    media_retry_error_http_headers_dict_items_dict_items: Optional[list] = None
    media_retry_error_http_headers_dict_keys_dict_items: Optional[list] = None
    media_retry_error_http_headers_dict_values_dict_items: Optional[list] = None
    media_retry_error_http_headers_dict_items_dict_keys: Optional[list] = None
    media_retry_error_http_headers_dict_keys_dict_keys: Optional[list] = None
    media_retry_error_http_headers_dict_values_dict_keys: Optional[list] = None
    media_retry_error_http_headers_dict_items_dict_values: Optional[list] = None
    media_retry_error_http_headers_dict_keys_dict_values: Optional[list] = None
    media_retry_error_http_headers_dict_values_dict_values: Optional[list] = None

    def __post_init__(self):
        if self.key is None and self.message is not None and hasattr(self.message, 'key'):
            self.key = self.message.key
