"""
WhatsApp message sending functionality.

Port of whatsmeow/send.go
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Tuple
import struct

from ..generated.waE2E import waE2E_pb2
from ..generated.waMsgApplication import waMsgApplication_pb2
from ..generated.waMsgTransport import waMsgTransport_pb2
from ..generated.waCommon import waCommon_pb2
from ..generated.waConsumerApplication import waConsumerApplication_pb2

from .types.jid import JID
from .types.message import MessageID, MessageInfo
from .binary.node import Node
from .binary import waBinary_pb2 as waBinary
from .exceptions import WhatsAppError, IQError

# TODO: Verify import when store is ported
from .store import Store
# TODO: Verify import when retry is ported
from .retry import RetryHandler
# TODO: Verify import when request is ported
from .request import RequestMixin
# TODO: Verify import when internals is ported
from .internals import InternalsMixin

# Constants
WEB_MESSAGE_ID_PREFIX = "3EB0"
DISAPPEARING_TIMER_OFF = "0"
DISAPPEARING_TIMER_24H = "86400"
DISAPPEARING_TIMER_7D = "604800"
DISAPPEARING_TIMER_90D = "7776000"
EDIT_WINDOW = timedelta(minutes=15)
REMOVE_REACTION_TEXT = ""

# Message types for routing
MESSAGE_TYPE_REGULAR = "regular"
MESSAGE_TYPE_PEER = "peer"
MESSAGE_TYPE_GROUP = "group"


@dataclass
class MessageDebugTimings:
    """Debug timing information for message sending."""
    queue: float = 0.0
    marshal: float = 0.0
    get_participants: float = 0.0
    asm_participants: float = 0.0
    encrypt: float = 0.0
    send: float = 0.0
    resp: float = 0.0
    retry: float = 0.0


@dataclass
class SendResponse:
    """Response from sending a message."""
    timestamp: datetime
    message_id: MessageID
    debug_timings: Optional[MessageDebugTimings] = None


@dataclass
class SendRequestExtra:
    """Optional parameters for SendMessage."""
    # The message ID to use when sending. If this is not provided, a random message ID will be generated
    id: MessageID = ""

    # JID of the bot to be invoked (optional)
    inline_bot_jid: JID = field(default_factory=JID)

    # Should the message be sent as a peer message (protocol messages to your own devices, e.g. app state key requests)
    peer: bool = False

    # A timeout for the send request. Unlike timeouts using the context parameter, this only applies
    # to the actual response waiting and not preparing/encrypting the message.
    # Defaults to 75 seconds. The timeout can be disabled by using a negative value.
    timeout: timedelta = timedelta(seconds=75)

    # When sending media to newsletters, the Handle field returned by the file upload.
    media_handle: str = ""

    # Message metadata information
    meta: Optional[Dict[str, Any]] = None


def generate_message_id() -> MessageID:
    """Generate a random message ID."""
    return WEB_MESSAGE_ID_PREFIX + secrets.token_hex(8).upper()


def generate_facebook_message_id() -> MessageID:
    """Generate a Facebook-style message ID."""
    return "m_" + secrets.token_hex(16)


def parse_disappearing_timer_string(val: str) -> timedelta:
    """Parse disappearing timer string to timedelta."""
    if val == DISAPPEARING_TIMER_OFF or val == "":
        return timedelta(0)
    try:
        seconds = int(val)
        return timedelta(seconds=seconds)
    except ValueError:
        return timedelta(0)


def participant_list_hash_v2(participants: List[JID]) -> bytes:
    """Generate hash of participant list for groups (version 2)."""
    # Sort participants by their string representation
    sorted_participants = sorted(str(jid) for jid in participants)

    # Create hash input
    hash_input = b""
    for participant in sorted_participants:
        hash_input += participant.encode('utf-8') + b'\x00'

    # Use SHA-256 for hashing
    import hashlib
    return hashlib.sha256(hash_input).digest()


def get_type_from_message(message: waE2E_pb2.Message) -> str:
    """Get message type from protobuf message."""
    if message.HasField('conversation'):
        return 'conversation'
    elif message.HasField('imageMessage'):
        return 'image'
    elif message.HasField('videoMessage'):
        return 'video'
    elif message.HasField('audioMessage'):
        return 'audio'
    elif message.HasField('documentMessage'):
        return 'document'
    elif message.HasField('contactMessage'):
        return 'contact'
    elif message.HasField('locationMessage'):
        return 'location'
    elif message.HasField('extendedTextMessage'):
        return 'extendedText'
    elif message.HasField('stickerMessage'):
        return 'sticker'
    elif message.HasField('reactionMessage'):
        return 'reaction'
    elif message.HasField('editedMessage'):
        return 'edited'
    else:
        return 'unknown'


def get_media_type_from_message(message: waE2E_pb2.Message) -> Optional[str]:
    """Get media type from message if it contains media."""
    if message.HasField('imageMessage'):
        return 'image'
    elif message.HasField('videoMessage'):
        return 'video'
    elif message.HasField('audioMessage'):
        return 'audio'
    elif message.HasField('documentMessage'):
        return 'document'
    elif message.HasField('stickerMessage'):
        return 'sticker'
    return None


def get_button_type_from_message(message: waE2E_pb2.Message) -> Optional[str]:
    """Get button type from message if it contains buttons."""
    if message.HasField('buttonsMessage'):
        return 'buttons'
    elif message.HasField('templateMessage'):
        return 'template'
    elif message.HasField('listMessage'):
        return 'list'
    return None


def get_button_attributes(message: waE2E_pb2.Message) -> Dict[str, str]:
    """Get button attributes from message."""
    attrs = {}

    if message.HasField('buttonsMessage'):
        attrs['type'] = 'buttons'
        if message.buttonsMessage.HasField('headerText'):
            attrs['header'] = message.buttonsMessage.headerText
    elif message.HasField('templateMessage'):
        attrs['type'] = 'template'
        if message.templateMessage.HasField('fourRowTemplate'):
            attrs['template_type'] = 'four_row'
    elif message.HasField('listMessage'):
        attrs['type'] = 'list'
        if message.listMessage.HasField('title'):
            attrs['title'] = message.listMessage.title

    return attrs


def get_edit_attribute(message: waE2E_pb2.Message) -> Optional[str]:
    """Get edit attribute from message if it's an edit."""
    if message.HasField('editedMessage'):
        if message.editedMessage.HasField('message'):
            return 'sender_revoke'
    return None


def marshal_message(message: waE2E_pb2.Message) -> bytes:
    """Marshal protobuf message to bytes."""
    return message.SerializeToString()


def apply_bot_message_hkdf(message_key: bytes, bot_jid: JID) -> bytes:
    """Apply HKDF for bot message encryption."""
    # TODO: Verify import when hkdfutil is ported
    from .util.hkdfutil import hkdf_expand

    info = f"WhatsApp Bot Message {bot_jid}".encode('utf-8')
    return hkdf_expand(message_key, 32, info)


class SendMixin:
    """Mixin providing message sending functionality."""

    def __init__(self):
        self.log: logging.Logger = logging.getLogger(__name__)
        # TODO: Verify when store is ported
        self.store: Store = None
        # TODO: Verify when retry is ported
        self.retry_handler: RetryHandler = None

    def generate_message_id(self) -> MessageID:
        """Generate a message ID for this client."""
        return generate_message_id()

    async def send_message(
        self,
        to: JID,
        message: waE2E_pb2.Message,
        extra: Optional[SendRequestExtra] = None
    ) -> SendResponse:
        """
        Send a message to a JID.

        Args:
            to: Target JID to send message to
            message: Message content to send
            extra: Optional extra parameters

        Returns:
            SendResponse with timestamp and message ID

        Raises:
            WhatsAppError: If sending fails
        """
        if extra is None:
            extra = SendRequestExtra()

        # Generate message ID if not provided
        if not extra.id:
            extra.id = self.generate_message_id()

        debug_timings = MessageDebugTimings()
        start_time = time.time()

        try:
            # Marshal message
            marshal_start = time.time()
            message_bytes = marshal_message(message)
            debug_timings.marshal = time.time() - marshal_start

            # Determine message routing
            if extra.peer:
                return await self._send_peer_message(to, message, extra, debug_timings)
            elif to.is_group():
                return await self._send_group_message(to, message, extra, debug_timings)
            else:
                return await self._send_dm_message(to, message, extra, debug_timings)

        except Exception as e:
            self.log.error(f"Failed to send message to {to}: {e}")
            raise WhatsAppError(f"Failed to send message: {e}") from e

    async def _send_peer_message(
        self,
        to: JID,
        message: waE2E_pb2.Message,
        extra: SendRequestExtra,
        debug_timings: MessageDebugTimings
    ) -> SendResponse:
        """Send a peer message (to own devices)."""
        # TODO: Implement peer message encryption and sending
        # This requires Signal protocol session management
        raise NotImplementedError("Peer message sending not yet implemented")

    async def _send_group_message(
        self,
        to: JID,
        message: waE2E_pb2.Message,
        extra: SendRequestExtra,
        debug_timings: MessageDebugTimings
    ) -> SendResponse:
        """Send a message to a group."""
        # TODO: Implement group message encryption
        # This requires Signal protocol group encryption
        raise NotImplementedError("Group message sending not yet implemented")

    async def _send_dm_message(
        self,
        to: JID,
        message: waE2E_pb2.Message,
        extra: SendRequestExtra,
        debug_timings: MessageDebugTimings
    ) -> SendResponse:
        """Send a direct message."""
        # TODO: Implement DM encryption and sending
        # This requires Signal protocol session management
        raise NotImplementedError("DM message sending not yet implemented")

    def build_message_key(self, to: JID, message_id: MessageID) -> Dict[str, Any]:
        """Build message key for WhatsApp protocol."""
        key = {
            'id': message_id,
            'remoteJid': str(to),
        }

        if to.is_group():
            key['participant'] = str(self.store.id)  # TODO: Verify when store is ported

        return key

    async def get_message_target(self, to: JID, is_group: bool) -> Tuple[JID, List[JID]]:
        """Get message target and participants for encryption."""
        if is_group:
            # TODO: Get group participants
            # This requires group management functionality
            participants = []  # Placeholder
            return to, participants
        else:
            return to, [to]

    async def encrypt_message_for_device(
        self,
        to: JID,
        message_bytes: bytes,
        message_key: Dict[str, Any]
    ) -> bytes:
        """Encrypt message for a specific device using Signal protocol."""
        # TODO: Implement Signal protocol encryption
        # This requires session store and encryption utilities
        raise NotImplementedError("Message encryption not yet implemented")

    async def send_encrypted_message(
        self,
        to: JID,
        encrypted_message: bytes,
        message_key: Dict[str, Any],
        extra: SendRequestExtra
    ) -> SendResponse:
        """Send encrypted message via WhatsApp protocol."""
        # TODO: Implement actual network sending
        # This requires request/IQ functionality

        # Build message node
        message_node = Node(
            tag="message",
            attrs={
                'to': str(to),
                'id': message_key['id'],
                'type': 'text'  # This should be determined from message content
            },
            content=encrypted_message
        )

        # TODO: Send via send_iq or similar
        # timestamp = await self.send_iq(message_node, timeout=extra.timeout)

        # Placeholder response
        timestamp = datetime.now()

        # Add to retry handler
        if self.retry_handler:
            # TODO: Verify when retry is ported
            pass  # self.retry_handler.add_recent_message(to, message_key['id'], message, None)

        return SendResponse(
            timestamp=timestamp,
            message_id=message_key['id']
        )

    # Edit and reaction support
    async def send_edit_message(
        self,
        to: JID,
        original_id: MessageID,
        new_content: waE2E_pb2.Message
    ) -> SendResponse:
        """Send an edit for an existing message."""
        # Build edit message
        edit_message = waE2E_pb2.Message()
        edit_message.editedMessage.message.CopyFrom(new_content)
        edit_message.editedMessage.key.id = original_id
        edit_message.editedMessage.key.remoteJid = str(to)

        if to.is_group():
            edit_message.editedMessage.key.participant = str(self.store.id)

        extra = SendRequestExtra(id=self.generate_message_id())
        return await self.send_message(to, edit_message, extra)

    async def send_reaction(
        self,
        to: JID,
        message_id: MessageID,
        reaction: str,
        remove: bool = False
    ) -> SendResponse:
        """Send a reaction to a message."""
        reaction_message = waE2E_pb2.Message()
        reaction_message.reactionMessage.key.id = message_id
        reaction_message.reactionMessage.key.remoteJid = str(to)

        if to.is_group():
            reaction_message.reactionMessage.key.participant = str(self.store.id)

        if not remove:
            reaction_message.reactionMessage.text = reaction
        # For removal, text is left empty

        extra = SendRequestExtra(id=self.generate_message_id())
        return await self.send_message(to, reaction_message, extra)

    # Newsletter support
    async def send_newsletter_message(
        self,
        to: JID,
        message: waE2E_pb2.Message,
        extra: Optional[SendRequestExtra] = None
    ) -> SendResponse:
        """Send a message to a newsletter/channel."""
        if extra is None:
            extra = SendRequestExtra()

        # Newsletter messages have special handling
        if extra.media_handle:
            # TODO: Handle media in newsletters with upload handle
            pass

        # Newsletter messages are sent differently than regular messages
        # TODO: Implement newsletter-specific sending logic
        raise NotImplementedError("Newsletter message sending not yet implemented")

    # Utility methods
    def is_edit_window_open(self, original_timestamp: datetime) -> bool:
        """Check if message is still within edit window."""
        return datetime.now() - original_timestamp <= EDIT_WINDOW

    def validate_message_for_edit(self, message: waE2E_pb2.Message) -> bool:
        """Validate that message can be edited."""
        # Only certain message types can be edited
        return (message.HasField('conversation') or
                message.HasField('extendedTextMessage') or
                message.HasField('imageMessage') or
                message.HasField('videoMessage') or
                message.HasField('documentMessage'))

    async def get_message_info_for_retry(
        self,
        to: JID,
        message_id: MessageID
    ) -> Optional[MessageInfo]:
        """Get message info for retry receipt handling."""
        # TODO: This should integrate with retry handler
        # return self.retry_handler.get_recent_message(to, message_id)
        return None
