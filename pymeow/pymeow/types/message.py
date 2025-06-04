"""
Message types for PyMeow.

Port of whatsmeow/types/message.go
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any

from ..types.jid import JID


class AddressingMode(str, Enum):
    """Addressing modes for messages."""
    PN = "pn"
    LID = "lid"


@dataclass
class MessageSource:
    """Contains basic sender and chat information about a message.

    Attributes:
        chat: The chat where the message was sent.
        sender: The user who sent the message.
        is_from_me: Whether the message was sent by the current user instead of someone else.
        is_group: Whether the chat is a group chat or broadcast list.
        addressing_mode: The addressing mode of the message (phone number or LID).
        sender_alt: The alternative address of the user who sent the message.
        recipient_alt: The alternative address of the recipient of the message for DMs.
        broadcast_list_owner: When sending a read receipt to a broadcast list message, the Chat is the broadcast list
                             and Sender is you, so this field contains the recipient of the read receipt.
    """
    chat: JID = field(default_factory=lambda: JID(user="", server=""))
    sender: JID = field(default_factory=lambda: JID(user="", server=""))
    is_from_me: bool = False
    is_group: bool = False
    addressing_mode: Optional[AddressingMode] = None
    sender_alt: JID = field(default_factory=lambda: JID(user="", server=""))
    recipient_alt: JID = field(default_factory=lambda: JID(user="", server=""))
    broadcast_list_owner: JID = field(default_factory=lambda: JID(user="", server=""))

    def is_incoming_broadcast(self) -> bool:
        """Returns true if the message was sent to a broadcast list instead of directly to the user.

        If this is true, it means the message shows up in the direct chat with the Sender.
        """
        return (not self.is_from_me or not self.broadcast_list_owner.is_empty()) and self.chat.is_broadcast_list()

    def source_string(self) -> str:
        """Returns a log-friendly representation of who sent the message and where."""
        if self.sender != self.chat:
            return f"{self.sender} in {self.chat}"
        else:
            return str(self.chat)


@dataclass
class DeviceSentMeta:
    """Contains metadata from messages sent by another one of the user's own devices.

    Attributes:
        destination_jid: The destination user. This should match the MessageInfo.Recipient field.
        phash: The phash value.
    """
    destination_jid: str = ""
    phash: str = ""


class EditAttribute(str, Enum):
    """Edit attributes for messages."""
    EMPTY = ""
    MESSAGE_EDIT = "1"
    PIN_IN_CHAT = "2"
    ADMIN_EDIT = "3"  # only used in newsletters
    SENDER_REVOKE = "7"
    ADMIN_REVOKE = "8"


class BotEditType(str, Enum):
    """Bot edit types for messages."""
    FIRST = "first"
    INNER = "inner"
    LAST = "last"


class MessageID(str):
    """Message ID type."""
    pass


class MessageServerID(int):
    """Message server ID type."""
    pass


@dataclass
class MsgBotInfo:
    """Bot information for messages.

    Attributes:
        edit_type: The type of edit.
        edit_target_id: The target message ID for the edit.
        edit_sender_timestamp_ms: The timestamp of the edit.
    """
    edit_type: Optional[BotEditType] = None
    edit_target_id: Optional[MessageID] = None
    edit_sender_timestamp_ms: Optional[datetime] = None


@dataclass
class MsgMetaInfo:
    """Meta information for messages.

    Attributes:
        target_id: The target message ID.
        target_sender: The JID of the target sender.
        deprecated_lid_session: Deprecated LID session flag.
        thread_message_id: The ID of the thread message.
        thread_message_sender_jid: The JID of the thread message sender.
    """
    target_id: Optional[MessageID] = None
    target_sender: JID = field(default_factory=lambda: JID(user="", server=""))
    deprecated_lid_session: Optional[bool] = None
    thread_message_id: Optional[MessageID] = None
    thread_message_sender_jid: JID = field(default_factory=lambda: JID(user="", server=""))


@dataclass
class MessageInfo:
    """Contains metadata about an incoming message.

    Attributes:
        message_source: Basic sender and chat information.
        id: The message ID.
        server_id: The server ID of the message.
        type: The message type.
        push_name: The push name.
        timestamp: The timestamp of the message.
        category: The message category.
        multicast: Whether the message is multicast.
        media_type: The media type of the message.
        edit: The edit attribute of the message.
        msg_bot_info: Bot information for the message.
        msg_meta_info: Meta information for the message.
        verified_name: The verified name information.
        device_sent_meta: Metadata for direct messages sent from another one of the user's own devices.
    """
    message_source: MessageSource = field(default_factory=lambda: MessageSource())
    id: Optional[MessageID] = None
    server_id: Optional[MessageServerID] = None
    type: str = ""
    push_name: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    category: str = ""
    multicast: bool = False
    media_type: str = ""
    edit: EditAttribute = EditAttribute.EMPTY
    msg_bot_info: MsgBotInfo = field(default_factory=lambda: MsgBotInfo())
    msg_meta_info: MsgMetaInfo = field(default_factory=lambda: MsgMetaInfo())
    verified_name: Any = None  # VerifiedName type not yet ported
    device_sent_meta: Optional[DeviceSentMeta] = None

    @property
    def sender(self):
        """Get the sender JID from the message source."""
        return self.message_source.sender

    @property
    def chat(self):
        """Get the chat JID from the message source."""
        return self.message_source.chat

    @property
    def sender_alt(self):
        """Get the alternative sender JID from the message source."""
        return self.message_source.sender_alt

    @property
    def recipient_alt(self):
        """Get the alternative recipient JID from the message source."""
        return self.message_source.recipient_alt

    def source_string(self) -> str:
        """Returns a log-friendly representation of who sent the message and where."""
        return self.message_source.source_string()

    @property
    def is_from_me(self):
        """Get the is_from_me flag from the message source."""
        return self.message_source.is_from_me
