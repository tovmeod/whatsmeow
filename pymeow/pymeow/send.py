"""
WhatsApp message sending functionality.

Port of whatsmeow/send.go
"""
import base64
import asyncio
import hashlib
import logging
import os
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, TYPE_CHECKING, List, Tuple
from warnings import deprecated

from . import prekeys
from .broadcast import get_broadcast_list_participants
from .exceptions import ErrRecipientADJID, ErrNotLoggedIn, ErrInvalidInlineBotID, ErrUnknownServer, ErrMessageTimedOut, \
    ErrServerReturnedError, ErrNoSession
from .group import get_cached_group_data, send_group_iq
from .message import migrate_session_store, clear_untrusted_identity, pad_message
from .msgsecret import apply_bot_message_hkdf
from .binary.node import Node, Attrs
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from .generated.waCommon import WACommon_pb2
from .prekeys import fetch_pre_keys
from .request import wait_response, cancel_response, retry_frame, is_disconnect_node, InfoQueryType
from .store.signal import contains_session
from .types import events
from .types.jid import JID, DEFAULT_USER_SERVER, GROUP_SERVER, BROADCAST_SERVER, HIDDEN_USER_SERVER, BOT_SERVER, \
    NEWSLETTER_SERVER, MESSENGER_SERVER
from .types.message import MessageID, MessageServerID, AddressingMode, MsgMetaInfo, EditAttribute, MessageInfo
from .user import get_user_devices_context

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)

# Constants
WEB_MESSAGE_ID_PREFIX = "3EB0"
DEFAULT_REQUEST_TIMEOUT = timedelta(seconds=75)
REMOVE_REACTION_TEXT = ""

# Error constants
class WhatsAppErrors:
    CLIENT_IS_NIL = "Client is None"
    RECIPIENT_AD_JID = "Cannot send message to specific device without peer mode"
    NOT_LOGGED_IN = "Not logged in"
    INVALID_INLINE_BOT_ID = "Invalid inline bot ID"
    MESSAGE_TIMED_OUT = "Message timed out"
    SERVER_RETURNED_ERROR = "Server returned error"
    UNKNOWN_SERVER = "Unknown server"

@dataclass
class MessageDebugTimings:
    """Debug timing information for message sending."""
    queue: timedelta = timedelta()
    marshal: timedelta = timedelta()
    get_participants: timedelta = timedelta()
    get_devices: timedelta = timedelta()
    group_encrypt: timedelta = timedelta()
    peer_encrypt: timedelta = timedelta()
    send: timedelta = timedelta()
    resp: timedelta = timedelta()
    retry: timedelta = timedelta()

@dataclass
class SendResponse:
    """Response from sending a message."""
    timestamp: Optional[datetime] = None
    id: Optional[MessageID] = None
    server_id: MessageServerID = MessageServerID(0)
    debug_timings: MessageDebugTimings = None
    sender: JID = None

    def __post_init__(self):
        if self.debug_timings is None:
            self.debug_timings = MessageDebugTimings()
        if self.sender is None:
            self.sender = JID()

@dataclass
class SendRequestExtra:
    """Optional parameters for SendMessage."""
    id: Optional[MessageID] = None
    inline_bot_jid: JID = None
    peer: bool = False
    # A timeout for the send request. Unlike timeouts using the context parameter, this only applies
    # to the actual response waiting and not preparing/encrypting the message.
    # Defaults to 75 seconds. The timeout can be disabled by using a negative value.
    timeout: timedelta = timedelta(seconds=75)
    # When sending media to newsletters, the Handle field returned by the file upload.
    media_handle: str = ""
    meta: Optional[MsgMetaInfo] = None

    def __post_init__(self):
        if self.inline_bot_jid is None:
            self.inline_bot_jid = JID()

@dataclass
class NodeExtraParams:
    """Extra parameters for node creation."""
    addressing_mode: Optional[AddressingMode] = None
    bot_node: Optional[Any] = None
    meta_node: Optional[Any] = None


def generate_message_id(client: "Client") -> MessageID:
    """
    Port of Go method GenerateMessageID from client.go.

    Generates a random string that can be used as a message ID on WhatsApp.

    Example:
        msg_id = cli.generate_message_id()
        cli.send_message(context.Background(), target_jid, waE2E.Message(...),
                        whatsmeow.SendRequestExtra(id=msg_id))

    Returns:
        Generated message ID string
    """
    # TODO: Review MessengerConfig implementation
    # TODO: Review generate_facebook_message_id implementation
    # TODO: Review WEB_MESSAGE_ID_PREFIX implementation
    # TODO: Review get_own_id implementation

    if client.messenger_config is not None:
        return MessageID(str(generate_facebook_message_id()))

    # Create initial 8-byte buffer for timestamp, with capacity for additional data
    data = bytearray(8)
    struct.pack_into('>Q', data, 0, int(time.time()))

    own_id = client.get_own_id()
    if not own_id.is_empty():
        data.extend(own_id.user.encode())
        data.extend(b"@c.us")

    data.extend(secrets.token_bytes(16))
    hash_obj = hashlib.sha256(data)
    return MessageID(WEB_MESSAGE_ID_PREFIX + hash_obj.hexdigest()[:18].upper())


def generate_facebook_message_id() -> int:
    """
    Port of Go function GenerateFacebookMessageID.

    Generates a Facebook-style message ID using timestamp and random bits.

    Returns:
        64-bit integer message ID
    """
    # TODO: Review random.Bytes implementation

    RANDOM_MASK = (1 << 22) - 1

    timestamp_ms = int(time.time() * 1000)  # UnixMilli equivalent
    random_bytes = secrets.token_bytes(4)
    random_uint32 = struct.unpack('>I', random_bytes)[0]  # BigEndian.Uint32 equivalent

    return (timestamp_ms << 22) | (random_uint32 & RANDOM_MASK)


@deprecated("Use Client.generate_message_id instead")
def deprecated_generate_message_id() -> MessageID:
    """
    Generate a random string that can be used as a message ID on WhatsApp.

    Deprecated: WhatsApp web has switched to using a hash of the current timestamp,
    user id and random bytes. Use Client.generate_message_id instead.
    """


def marshal_zerolog_object(client: "Client", evt: 'zerolog.Event') -> None:
    """
    Port of Go method MarshalZerologObject from MessageDebugTimings.

    Marshals MessageDebugTimings data into a zerolog Event for structured logging.

    Args:
        evt: Zerolog event to add timing data to

    Returns:
        None
    """
    # TODO: Review zerolog.Event implementation
    # TODO: Review Event.dur method implementation

    evt.dur("queue", self.queue)
    evt.dur("marshal", self.marshal)
    if self.get_participants != 0:
        evt.dur("get_participants", self.get_participants)
    evt.dur("get_devices", self.get_devices)
    if self.group_encrypt != 0:
        evt.dur("group_encrypt", self.group_encrypt)
    evt.dur("peer_encrypt", self.peer_encrypt)
    evt.dur("send", self.send)
    evt.dur("resp", self.resp)
    if self.retry != 0:
        evt.dur("retry", self.retry)



async def send_message(
    client: 'Client',
    to: JID,
    message: waE2E_pb2.Message,
    *extra: SendRequestExtra
) -> Tuple[Optional[SendResponse], Optional[Exception]]:
    """
    Port of Go method SendMessage from client.go.

    Sends the given message.

    This method will wait for the server to acknowledge the message before returning.
    The return value is the timestamp of the message from the server.

    Optional parameters like the message ID can be specified with the SendRequestExtra struct.
    Only one extra parameter is allowed, put all necessary parameters in the same struct.

    The message itself can contain anything you want (within the protobuf schema).
    e.g. for a simple text message, use the Conversation field:

        cli.send_message(context.Background(), target_jid, waE2E_pb2.Message(
            conversation="Hello, World!"
        ))

    Things like replies, mentioning users and the "forwarded" flag are stored in ContextInfo,
    which can be put in ExtendedTextMessage and any of the media message types.

    For uploading and sending media/attachments, see the Upload method.

    For other message types, you'll have to figure it out yourself. Looking at the protobuf schema
    in binary/proto/def.proto may be useful to find out all the allowed fields. Printing the RawMessage
    field in incoming message events to figure out what it contains is also a good way to learn how to
    send the same kind of message.

    Args:
        ctx: Context for the operation
        to: Target JID to send message to
        message: Message protobuf to send
        extra: Optional SendRequestExtra parameters

    Returns:
        Tuple containing (SendResponse, error) - matches Go's multiple return pattern
    """
    # TODO: Review ErrClientIsNil implementation
    # TODO: Review SendRequestExtra implementation
    # TODO: Review SendResponse implementation
    # TODO: Review ErrRecipientADJID implementation
    # TODO: Review ErrNotLoggedIn implementation
    # TODO: Review default_request_timeout implementation
    # TODO: Review generate_message_id implementation
    # TODO: Review types.NewsletterServer implementation
    # TODO: Review ErrInvalidInlineBotID implementation
    # TODO: Review random.Bytes implementation
    # TODO: Review nodeExtraParams implementation
    # TODO: Review marshalMessage implementation
    # TODO: Review encrypt_message_for_devices implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review getCachedGroupData implementation
    # TODO: Review getBroadcastListParticipants implementation
    # TODO: Review types.AddressingModeLID implementation
    # TODO: Review types.AddressingModePN implementation
    # TODO: Review types.HiddenUserServer implementation
    # TODO: Review ptr.Ptr implementation
    # TODO: Review wait_response implementation
    # TODO: Review add_recent_message implementation
    # TODO: Review send_group implementation
    # TODO: Review send_peer_message implementation
    # TODO: Review send_dm implementation
    # TODO: Review send_newsletter implementation
    # TODO: Review ErrUnknownServer implementation
    # TODO: Review cancel_response implementation
    # TODO: Review ErrMessageTimedOut implementation
    # TODO: Review is_disconnect_node implementation
    # TODO: Review retry_frame implementation
    # TODO: Review ErrServerReturnedError implementation

    from . import retry

    req = SendRequestExtra()
    if len(extra) > 1:
        return None, Exception("only one extra parameter may be provided to SendMessage")
    elif len(extra) == 1:
        req = extra[0]

    if to.device > 0 and not req.peer:
        return None, ErrRecipientADJID

    own_id = client.get_own_id()
    if own_id.is_empty():
        return None, ErrNotLoggedIn

    if req.timeout == timedelta():
        req.timeout = DEFAULT_REQUEST_TIMEOUT
    if len(req.id) == 0:
        req.id = generate_message_id()
    if to.server == NEWSLETTER_SERVER:
        # TODO somehow deduplicate this with the code in send_newsletter?
        if message.edited_message is not None:
            req.id = MessageID(message.edited_message.message.protocol_message.key.id)
        elif message.protocol_message is not None and message.protocol_message.type == waE2E_pb2.ProtocolMessage.REVOKE:
            req.id = MessageID(message.protocol_message.key.id)

    resp = SendResponse()
    resp.id = req.id

    is_inline_bot_mode = False

    if not req.inline_bot_jid.is_empty():
        if not req.inline_bot_jid.is_bot():
            return None, ErrInvalidInlineBotID
        is_inline_bot_mode = True

    is_bot_mode = is_inline_bot_mode or to.is_bot()
    needs_message_secret = is_bot_mode
    extra_params = NodeExtraParams()

    if needs_message_secret:
        if message.message_context_info is None:
            message.message_context_info = waE2E_pb2.MessageContextInfo()
        if message.message_context_info.message_secret is None:
            message.message_context_info.message_secret = os.urandom(32)

    if is_bot_mode:
        if message.message_context_info.bot_metadata is None:
            message.message_context_info.bot_metadata = waE2E_pb2.BotMetadata()
            message.message_context_info.bot_metadata.persona_id = "867051314767696$760019659443059"

        if is_inline_bot_mode:
            # inline mode specific code
            message_secret = message.message_context_info.message_secret
            message = waE2E_pb2.Message(
                botInvokeMessage=waE2E_pb2.FutureProofMessage(
                    message=waE2E_pb2.Message(
                        extendedTextMessage=message.extended_text_message,
                        messageContextInfo=waE2E_pb2.MessageContextInfo(
                            botMetadata=message.message_context_info.bot_metadata,
                        ),
                    ),
                ),
                messageContextInfo=message.message_context_info,
            )

            bot_message = waE2E_pb2.Message(
                botInvokeMessage=message.bot_invoke_message,
                messageContextInfo=waE2E_pb2.MessageContextInfo(
                    botMetadata=message.message_context_info.bot_metadata,
                    botMessageSecret=apply_bot_message_hkdf(message_secret),
                ),
            )

            message_plaintext, _, marshal_err = marshal_message(req.inline_bot_jid, bot_message)
            if marshal_err is not None:
                return None, marshal_err

            participant_nodes, _ = await encrypt_message_for_devices(client, [req.inline_bot_jid], resp.id,
                                                                     message_plaintext, None, Attrs())
            extra_params.bot_node = Node(
                tag="bot",
                content=participant_nodes,
            )

    group_participants = []
    if to.server == GROUP_SERVER or to.server == BROADCAST_SERVER:
        start = time.time()
        if to.server == GROUP_SERVER:
            cached_data, err = await get_cached_group_data(client, to)
            if err is not None:
                return None, Exception(f"failed to get group members: {err}")
            group_participants = cached_data.members
            # TODO this is fairly hacky, is there a proper way to determine which identity the message is sent with?
            if cached_data.addressing_mode == AddressingMode.LID:
                own_id = client.get_own_lid()
                extra_params.addressing_mode = AddressingMode.LID
                if req.meta is None:
                    req.meta = MsgMetaInfo()
                req.meta.deprecated_lid_session = ptr.Ptr(False)
            elif cached_data.community_announcement_group and req.meta is not None:
                own_id = client.get_own_lid()
                # Why is this set to PN?
                extra_params.addressing_mode = AddressingMode.PN
        else:
            group_participants, err = await get_broadcast_list_participants(client, to)
            if err is not None:
                return None, Exception(f"failed to get broadcast list members: {err}")
        resp.debug_timings.get_participants = timedelta(seconds=time.time() - start)
    elif to.server == HIDDEN_USER_SERVER:
        own_id = client.get_own_lid()
        extra_params.addressing_mode = AddressingMode.LID
        # if req.meta is None:
        #     req.meta = types.MsgMetaInfo()
        # req.meta.deprecated_lid_session = ptr.Ptr(False)

    if req.meta is not None:
        extra_params.meta_node = Node(
            tag="meta",
            attrs=Attrs(),
        )
        if req.meta.deprecated_lid_session is not None:
            extra_params.meta_node.attrs["deprecated_lid_session"] = req.meta.deprecated_lid_session
        if req.meta.thread_message_id != "":
            extra_params.meta_node.attrs["thread_msg_id"] = req.meta.thread_message_id
            extra_params.meta_node.attrs["thread_msg_sender_jid"] = req.meta.thread_message_sender_jid

    resp.sender = own_id

    start = time.time()
    # Sending multiple messages at a time can cause weird issues and makes it harder to retry safely
    async with client.message_send_lock:
        resp.debug_timings.queue = timedelta(seconds=time.time() - start)

        resp_chan = wait_response(client, req.id)
        # Peer message retries aren't implemented yet
        if not req.peer:
            retry.add_recent_message(client, to, req.id, message, None)

        if message.message_context_info is not None and message.message_context_info.message_secret is not None:
            err = await client.store.msg_secrets.put_message_secret(to, own_id, req.id,
                                                                  message.message_context_info.message_secret)
            if err is not None:
                logger.warning("Failed to store message secret key for outgoing message %s: %v", req.id, err)
            else:
                logger.debug("Stored message secret key for outgoing message %s", req.id)

        phash = ""
        data = None
        if to.server == GROUP_SERVER or to.server == BROADCAST_SERVER:
            phash, data, error = await send_group(client, to, group_participants, req.id, message, resp.debug_timings,
                                                  extra_params)
        elif to.server == DEFAULT_USER_SERVER or to.server == BOT_SERVER:
            if req.peer:
                data, err = await send_peer_message(client, to, req.id, message, resp.debug_timings)
            else:
                data, err = await send_dm(client, own_id, to, req.id, message, resp.debug_timings, extra_params)
        elif to.server == NEWSLETTER_SERVER:
            data, err = await send_newsletter(client, to, req.id, message, req.media_handle, resp.debug_timings)
        else:
            err = Exception(f"{ErrUnknownServer} {to.server}")

        start = time.time()
        if err is not None:
            await cancel_response(client, req.id, resp_chan)
            return None, err

        resp_node = None
        timeout_chan = None
        if req.timeout > timedelta():
            timeout_chan = asyncio.create_task(asyncio.sleep(req.timeout.total_seconds()))
        else:
            timeout_chan = asyncio.create_task(asyncio.sleep(float('inf')))  # Never times out

        try:
            done, pending = await asyncio.wait(
                [resp_chan, timeout_chan],
                return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()

            if timeout_chan in done:
                await cancel_response(client, req.id, resp_chan)
                return None, ErrMessageTimedOut
            else:
                resp_node = await resp_chan
        except asyncio.CancelledError as e:
            await cancel_response(client, req.id, resp_chan)
            return None, e

        resp.debug_timings.resp = timedelta(seconds=time.time() - start)

        if is_disconnect_node(resp_node):
            start = time.time()
            resp_node, err = await retry_frame(client, "message send", req.id, data, resp_node, 0)
            resp.debug_timings.retry = timedelta(seconds=time.time() - start)
            if err is not None:
                return None, err

        ag = resp_node.attr_getter()
        resp.server_id = MessageServerID(ag.optional_int("server_id"))
        resp.timestamp = ag.unix_time("t")
        error_code = ag.int("error")
        if error_code != 0:
            err = Exception(f"{ErrServerReturnedError} {error_code}")

        expected_phash = ag.optional_string("phash")
        if len(expected_phash) > 0 and phash != expected_phash:
            logger.warning(
                "Server returned different participant list hash when sending to %s. Some devices may not have received the message.",
                to)
            # TODO also invalidate device list caches
            async with client.group_cache_lock:
                if to in client.group_cache:
                    del client.group_cache[to]

    return resp, err


@deprecated("This method is deprecated in favor of build_revoke")
async def revoke_message(client: "Client", chat: JID, id: MessageID) -> SendResponse:
    """
    Delete the given message from everyone in the chat.

    This method will wait for the server to acknowledge the revocation message before returning.
    The return value is the timestamp of the message from the server.

    Deprecated: This method is deprecated in favor of build_revoke
    """
    revoke_msg = build_revoke(client, chat, JID(), id)
    send_response, error = await send_message(client, None, chat, revoke_msg)
    return send_response


def build_message_key(
    client: 'Client',
    chat: JID,
    sender: JID,
    id: MessageID
) -> WACommon_pb2.MessageKey:
    """
    Port of Go method BuildMessageKey from client.go.

    Builds a MessageKey object, which is used to refer to previous messages
    for things such as replies, revocations and reactions.

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat where the message was sent
        sender: JID of the message sender
        id: Message ID to reference

    Returns:
        MessageKey protobuf object for referencing the message
    """
    # TODO: Review MessageKey protobuf implementation
    # TODO: Review client.get_own_id() implementation
    # TODO: Review client.get_own_lid() implementation
    # TODO: Review types.DefaultUserServer, HiddenUserServer, MessengerServer constants

    key = WACommon_pb2.MessageKey()
    key.from_me = True
    key.id = str(id)
    key.remote_jid = str(chat)

    if (not sender.is_empty() and
        sender.user != client.get_own_id().user and
        sender.user != client.get_own_lid().user):
        key.from_me = False
        if (chat.server != DEFAULT_USER_SERVER and
            chat.server != HIDDEN_USER_SERVER and
            chat.server != MESSENGER_SERVER):
            key.participant = str(sender.to_non_ad())

    return key


def build_revoke(
    client: 'Client',
    chat: JID,
    sender: JID,
    id: MessageID
) -> waE2E_pb2.Message:
    """
    Port of Go method BuildRevoke from client.go.

    Builds a message revocation message using the given variables.
    The built message can be sent normally using send_message.

    To revoke your own messages, pass your JID or an empty JID as the second parameter (sender):
        resp = await send_message(client, ctx, chat, build_revoke(client, chat, types.EmptyJID, original_message_id))

    To revoke someone else's messages when you are group admin, pass the message sender's JID as the second parameter:
        resp = await send_message(client, ctx, chat, build_revoke(client, chat, sender_jid, original_message_id))

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat where the message was sent
        sender: JID of the message sender (or EmptyJID for own messages)
        id: Message ID to revoke

    Returns:
        Message protobuf containing the revocation protocol message
    """
    # TODO: Review build_message_key implementation
    # TODO: Review waE2E_pb2.ProtocolMessage.REVOKE enum value

    message = waE2E_pb2.Message()
    message.protocol_message.type = waE2E_pb2.ProtocolMessage.REVOKE
    message.protocol_message.key.CopyFrom(build_message_key(client, chat, sender, id))

    return message


def build_reaction(
    client: 'Client',
    chat: JID,
    sender: JID,
    id: MessageID,
    reaction: str
) -> waE2E_pb2.Message:
    """
    Port of Go method BuildReaction from client.go.

    Builds a message reaction message using the given variables.
    The built message can be sent normally using send_message.

        resp = await send_message(client, ctx, chat, build_reaction(client, chat, sender_jid, target_message_id, "🐈️"))

    Note that for newsletter messages, you need to use newsletter_send_reaction instead of build_reaction + send_message.

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat where the message was sent
        sender: JID of the message sender
        id: Message ID to react to
        reaction: Reaction emoji string

    Returns:
        Message protobuf containing the reaction message
    """
    # TODO: Review build_message_key implementation

    message = waE2E_pb2.Message()
    message.reaction_message.key.CopyFrom(build_message_key(client, chat, sender, id))
    message.reaction_message.text = reaction
    message.reaction_message.sender_timestamp_ms = int(time.time() * 1000)

    return message


def build_unavailable_message_request(
    client: 'Client',
    chat: JID,
    sender: JID,
    id: str
) -> waE2E_pb2.Message:
    """
    Port of Go method BuildUnavailableMessageRequest from client.go.

    Builds a message to request the user's primary device to send
    the copy of a message that this client was unable to decrypt.

    The built message can be sent using send_message, but you must pass SendRequestExtra(peer=True) as the last parameter.
    The full response will come as a ProtocolMessage with type `PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE`.
    The response events will also be dispatched as normal Message events with unavailable_request_id set to the request message ID.

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat where the message was sent
        sender: JID of the message sender
        id: Message ID string to request

    Returns:
        Message protobuf containing the unavailable message request
    """
    # TODO: Review build_message_key implementation
    # TODO: Review SendRequestExtra implementation

    message = waE2E_pb2.Message()
    message.protocol_message.type = waE2E_pb2.ProtocolMessage.PEER_DATA_OPERATION_REQUEST_MESSAGE

    # Create the peer data operation request message
    peer_request = message.protocol_message.peer_data_operation_request_message
    peer_request.peer_data_operation_request_type = waE2E_pb2.PeerDataOperationRequestType.PLACEHOLDER_MESSAGE_RESEND

    # Create placeholder message resend request
    resend_request = peer_request.placeholder_message_resend_request.add()
    resend_request.message_key.CopyFrom(build_message_key(client, chat, sender, id))

    return message


def build_history_sync_request(
    client: 'Client',
    last_known_message_info: MessageInfo,
    count: int
) -> waE2E_pb2.Message:
    """
    Port of Go method BuildHistorySyncRequest from client.go.

    Builds a message to request additional history from the user's primary device.

    The built message can be sent using send_message, but you must pass SendRequestExtra(peer=True) as the last parameter.
    The response will come as a HistorySync event with type `ON_DEMAND`.

    The response will contain up to `count` messages immediately before the given message.
    The recommended number of messages to request at a time is 50.

    Args:
        client: The WhatsApp client instance
        last_known_message_info: MessageInfo of the last known message to sync from
        count: Number of messages to request (recommended: 50)

    Returns:
        Message protobuf containing the history sync request
    """
    # TODO: Review types.MessageInfo implementation
    # TODO: Review SendRequestExtra implementation

    message = waE2E_pb2.Message()
    message.protocol_message.type = waE2E_pb2.ProtocolMessage.PEER_DATA_OPERATION_REQUEST_MESSAGE

    # Create the peer data operation request message
    peer_request = message.protocol_message.peer_data_operation_request_message
    peer_request.peer_data_operation_request_type = waE2E_pb2.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND

    # Create history sync on demand request
    history_request = peer_request.history_sync_on_demand_request
    history_request.chat_jid = str(last_known_message_info.chat)
    history_request.oldest_msg_id = str(last_known_message_info.id)
    history_request.oldest_msg_from_me = last_known_message_info.is_from_me
    history_request.on_demand_msg_count = count
    history_request.oldest_msg_timestamp_ms = int(last_known_message_info.timestamp.timestamp() * 1000)

    return message


def build_edit(
    client: 'Client',
    chat: JID,
    id: MessageID,
    new_content: waE2E_pb2.Message
) -> waE2E_pb2.Message:
    """
    Port of Go method BuildEdit from client.go.

    Builds a message edit message using the given variables.
    The built message can be sent normally using send_message.

        resp = await send_message(client, ctx, chat, build_edit(client, chat, original_message_id, waE2E_pb2.Message(
            conversation="edited message"
        )))

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat where the message was sent
        id: Message ID of the original message to edit
        new_content: New message content to replace the original

    Returns:
        Message protobuf containing the edit message
    """
    # TODO: Review waCommon_pb2.MessageKey implementation

    message = waE2E_pb2.Message()

    # Create the edited message structure
    edited_message = message.edited_message
    inner_message = edited_message.message
    protocol_message = inner_message.protocol_message

    # Set the message key
    protocol_message.key.from_me = True
    protocol_message.key.id = str(id)
    protocol_message.key.remote_jid = str(chat)

    # Set protocol message properties
    protocol_message.type = waE2E_pb2.ProtocolMessage.MESSAGE_EDIT
    protocol_message.edited_message.CopyFrom(new_content)
    protocol_message.timestamp_ms = int(time.time() * 1000)

    return message


def parse_disappearing_timer_string(val: str) -> Tuple[timedelta, bool]:
    """
    Port of Go method ParseDisappearingTimerString from client.go.

    Parses common human-readable disappearing message timer strings into timedelta values.
    If the string doesn't look like one of the allowed values (0, 24h, 7d, 90d), the second return value is False.

    Args:
        val: Human-readable timer string to parse

    Returns:
        Tuple containing (timedelta, success_bool) where:
        - timedelta: Parsed duration value
        - bool: True if parsing succeeded, False otherwise
    """
    # TODO: Review DISAPPEARING_TIMER_OFF implementation
    # TODO: Review DISAPPEARING_TIMER_24_HOURS implementation
    # TODO: Review DISAPPEARING_TIMER_7_DAYS implementation
    # TODO: Review DISAPPEARING_TIMER_90_DAYS implementation

    # Normalize the input string (remove spaces and convert to lowercase)
    normalized = val.replace(" ", "").lower()

    if normalized in ("0d", "0h", "0s", "0", "off"):
        return DISAPPEARING_TIMER_OFF, True
    elif normalized in ("1day", "day", "1d", "1", "24h", "24", "86400s", "86400"):
        return DISAPPEARING_TIMER_24_HOURS, True
    elif normalized in ("1week", "week", "7d", "7", "168h", "168", "604800s", "604800"):
        return DISAPPEARING_TIMER_7_DAYS, True
    elif normalized in ("3months", "3m", "3mo", "90d", "90", "2160h", "2160", "7776000s", "7776000"):
        return DISAPPEARING_TIMER_90_DAYS, True
    else:
        return timedelta(), False


def set_disappearing_timer(
    client: 'Client',
    chat: JID,
    timer: timedelta
) -> Optional[Exception]:
    """
    Port of Go method SetDisappearingTimer from client.go.

    Sets the disappearing timer in a chat. Both private chats and groups are supported, but they're
    set with different methods.

    Note that while this function allows passing non-standard durations, official WhatsApp apps will ignore those,
    and in groups the server will just reject the change. You can use the DISAPPEARING_TIMER_* constants for convenience.

    In groups, the server will echo the change as a notification, so it'll show up as a GroupInfo update.

    Args:
        client: The WhatsApp client instance
        chat: JID of the chat to set disappearing timer in
        timer: Duration for disappearing messages (use timedelta(0) to disable)

    Returns:
        Optional[Exception]: None if successful, Exception if error occurred
    """
    # TODO: Review send_message implementation
    # TODO: Review send_group_iq implementation
    # TODO: Review iqSet constant implementation
    # TODO: Review ErrIQBadRequest implementation
    # TODO: Review ErrInvalidDisappearingTimer implementation
    # TODO: Review wrap_iq_error implementation
    # TODO: Review types.DEFAULT_USER_SERVER implementation
    # TODO: Review types.GROUP_SERVER implementation

    try:
        if chat.server == DEFAULT_USER_SERVER:
            message = waE2E_pb2.Message()
            message.protocol_message.type = waE2E_pb2.ProtocolMessage.EPHEMERAL_SETTING
            message.protocol_message.ephemeral_expiration = int(timer.total_seconds())

            _, err = send_message(client, chat, message)
            return err

        elif chat.server == GROUP_SERVER:
            if timer == timedelta(0):
                node = Node(tag="not_ephemeral")
                _, err = send_group_iq(client, InfoQueryType.SET, chat, node)
            else:
                node = Node(
                    tag="ephemeral",
                    attrs=Attrs(expiration=str(int(timer.total_seconds())))
                )
                _, err = send_group_iq(client, None, InfoQueryType.SET, chat, node)  # context.TODO() -> None

                # TODO: Review error comparison and wrapping
                if err is not None:  # Simplified error handling - needs proper error type checking
                    pass  # Add proper error wrapping when error types are implemented

            return err
        else:
            return Exception(f"can't set disappearing time in a {chat.server} chat")
    except Exception as e:
        return e


def participant_list_hash_v2(participants: List[JID]) -> str:
    """
    Port of Go function participantListHashV2 from client.go.

    Generates a hash string for a list of participants using the same algorithm
    as the original Go implementation.

    Args:
        participants: List of JID participants

    Returns:
        Hash string in format "2:<base64_encoded_hash>"
    """
    # TODO: Review types.JID.ad_string implementation

    # Convert participants to strings using ADString method
    participant_strings = []
    for part in participants:
        participant_strings.append(part.ad_string())

    # Sort the strings
    participant_strings.sort()

    # Join all strings together
    joined_string = "".join(participant_strings)

    # Calculate SHA256 hash
    hash_bytes = hashlib.sha256(joined_string.encode()).digest()

    # Take first 6 bytes and encode with base64 (no padding)
    hash_truncated = hash_bytes[:6]
    encoded_hash = base64.b64encode(hash_truncated).decode().rstrip('=')

    return f"2:{encoded_hash}"


def send_newsletter(
    client: 'Client',
    to: JID,
    id: MessageID,
    message: Optional[waE2E_pb2.Message],
    media_id: str,
    timings: MessageDebugTimings
) -> Tuple[Optional[bytes], Optional[Exception]]:
    """
    Port of Go method sendNewsletter from client.go.

    Sends a newsletter message to the specified recipient.

    Args:
        client: The WhatsApp client instance
        to: Recipient JID
        id: Message ID
        message: The message to send
        media_id: Media ID if applicable
        timings: Debug timing information

    Returns:
        Tuple containing (response_data, error)
    """
    # TODO: Review get_type_from_message implementation
    # TODO: Review types.EditAttributeAdminEdit implementation
    # TODO: Review types.EditAttributeAdminRevoke implementation
    # TODO: Review marshal_message implementation
    # TODO: Review get_media_type_from_message implementation
    # TODO: Review send_node_and_get_data implementation

    try:
        attrs = Attrs({
            "to": str(to),
            "id": str(id),
            "type": get_type_from_message(message),
        })

        if media_id != "":
            attrs["media_id"] = media_id

        if message and message.edited_message is not None:
            attrs["edit"] = str(EditAttribute.ADMIN_EDIT)
            message = message.edited_message.message.protocol_message.edited_message
        elif (message and message.protocol_message is not None and
              message.protocol_message.type == waE2E_pb2.ProtocolMessage.REVOKE):
            attrs["edit"] = str(EditAttribute.ADMIN_REVOKE)
            message = None

        start = time.time()
        plaintext, _, err = marshal_message(to, message)
        timings.marshal = time.time() - start

        if err is not None:
            return None, err

        plaintext_node = Node(
            tag="plaintext",
            content=plaintext,
            attrs=Attrs({})
        )

        if message is not None:
            media_type = get_media_type_from_message(message)
            if media_type != "":
                plaintext_node.attrs["mediatype"] = media_type

        node = Node(
            tag="message",
            attrs=attrs,
            content=[plaintext_node]
        )

        start = time.time()
        data, err = client.send_node_and_get_data(node)
        timings.send = time.time() - start

        if err is not None:
            return None, Exception(f"failed to send message node: {err}")

        return data, None

    except Exception as e:
        return None, e


async def send_group(
    client: "Client",
    to: JID,
    participants: List[JID],
    id: MessageID,
    message: waE2E_pb2.Message,
    timings: MessageDebugTimings,
    extra_params: NodeExtraParams
) -> Tuple[str, Optional[bytes], Optional[Exception]]:
    """
    Port of Go method sendGroup from client.go.

    Sends a message to a group using sender key distribution for efficient group messaging.

    Args:
        to: Target group JID
        participants: List of participant JIDs
        id: Message ID
        message: Message protobuf to send
        timings: Debug timing tracker
        extra_params: Extra parameters for node construction

    Returns:
        Tuple containing (participant_hash, message_data, error)
    """
    # TODO: Review marshalMessage implementation
    # TODO: Review groups.NewGroupSessionBuilder implementation
    # TODO: Review pbSerializer implementation
    # TODO: Review protocol.NewSenderKeyName implementation
    # TODO: Review groups.NewGroupCipher implementation
    # TODO: Review padMessage implementation
    # TODO: Review prepareMessageNode implementation
    # TODO: Review participantListHashV2 implementation
    # TODO: Review getMediaTypeFromMessage implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review waBinary.Attrs implementation

    start = time.time()
    plaintext, _, err = marshal_message(to, message)
    timings.marshal = time.time() - start
    if err is not None:
        return "", None, err

    start = time.time()

    from signal_protocol import GroupSessionBuilder, GroupCipher, SenderKeyName

    builder = GroupSessionBuilder(client.store, pb_serializer)
    sender_key_name = SenderKeyName(str(to), client.get_own_lid().signal_address())
    try:
        signal_skd_message = await builder.create(ctx, sender_key_name)
    except Exception as err:
        return "", None, Exception(f"failed to create sender key distribution message to send {id} to {to}: {err}")

    skd_message = waE2E_pb2.Message()
    skd_message.sender_key_distribution_message.group_id = str(to)
    skd_message.sender_key_distribution_message.axolotl_sender_key_distribution_message = signal_skd_message.serialize()

    try:
        skd_plaintext = skd_message.SerializeToString()
    except Exception as err:
        return "", None, Exception(f"failed to marshal sender key distribution message to send {id} to {to}: {err}")

    cipher = GroupCipher(builder, sender_key_name, client.store)
    try:
        encrypted = await cipher.encrypt(ctx, pad_message(plaintext))
    except Exception as err:
        return "", None, Exception(f"failed to encrypt group message to send {id} to {to}: {err}")

    ciphertext = encrypted.signed_serialize()
    timings.group_encrypt = time.time() - start

    node, all_devices, err = await prepare_message_node(
        to, id, message, participants, skd_plaintext, None, timings, extra_params,
    )
    if err is not None:
        return "", None, err

    phash = participant_list_hash_v2(all_devices)
    node.attrs["phash"] = phash
    sk_msg = Node(
        tag="enc",
        content=ciphertext,
        attrs=Attrs({"v": "2", "type": "skmsg"}),
    )
    media_type = get_media_type_from_message(message)
    if media_type != "":
        sk_msg.attrs["mediatype"] = media_type
    node.content = node.get_children() + [sk_msg]

    start = time.time()
    data, err = await client.send_node_and_get_data(node)
    timings.send = time.time() - start
    if err is not None:
        return "", None, Exception(f"failed to send message node: {err}")

    return phash, data, None

async def send_peer_message(
    client: "Client",
    ctx,
    to_jid,
    message_id: str,
    message: waE2E_pb2.Message,
    timings
) -> bytes:
    """
    Send a peer message (protocol messages to your own devices).

    Peer messages are used for internal communication between your own devices,
    such as app state key requests, history sync requests, etc.

    Args:
        client: Client instance
        ctx: Context
        to_jid: Target JID (should be your own JID)
        message_id: Message ID
        message: Message object
        timings: Debug timings object

    Returns:
        Message data bytes
    """
    start_time = time.time()

    # Marshal the message
    msg_plaintext, dsm_plaintext, marshal_err = marshal_message(to_jid, message)
    timings.marshal = time.time() - start_time

    if marshal_err:
        raise marshal_err

    # Get devices for the target (your own devices)
    start_time = time.time()
    own_jid = client.get_own_id()

    # For peer messages, we need to get our own devices
    devices = await client.get_user_devices_cached([own_jid.to_non_ad()])
    own_devices = devices.get(own_jid.to_non_ad(), [])

    if not own_devices:
        # If no devices found, use the own JID itself
        own_devices = [own_jid.to_non_ad()]

    timings.get_devices = time.time() - start_time

    # Encrypt for own devices
    start_time = time.time()
    participant_nodes, _ = await encrypt_message_for_devices(
        client, ctx, own_devices, message_id, msg_plaintext, dsm_plaintext, {}
    )
    timings.peer_encrypt = time.time() - start_time

    if not participant_nodes:
        raise Exception("Failed to encrypt peer message for any devices")

    # Build message attributes
    message_attrs = Attrs({
        "id": message_id,
        "type": get_type_from_message(message),
        "to": str(to_jid),
        "peer": "true",  # Important: mark as peer message
    })

    # Create the message node
    message_node = Node(
        tag="message",
        attrs=message_attrs,
        content=participant_nodes
    )

    # Send the message
    start_time = time.time()
    data = await client.send_node_and_get_data(message_node)
    timings.send = time.time() - start_time

    if not data:
        raise Exception("Failed to send peer message node")

    return data

async def send_dm(
    client: "Client",
    own_id: JID,
    to: JID,
    id: MessageID,
    message: Optional[waE2E_pb2.Message],
    timings: MessageDebugTimings,
    extra_params: NodeExtraParams
) -> Tuple[Optional[bytes], Optional[Exception]]:
    """
    Port of Go method sendDM from client.go.

    Sends a direct message to a single user.

    Args:
        client: The WhatsApp client instance
        ctx: Context (asyncio context in Python)
        own_id: Own JID (sender)
        to: Target JID (recipient)
        id: Message ID
        message: The message to send
        timings: Debug timing information
        extra_params: Additional node parameters

    Returns:
        Tuple containing (response_data, error)
    """
    # TODO: Review marshal_message implementation
    # TODO: Review prepare_message_node implementation
    # TODO: Review send_node_and_get_data implementation

    try:
        start = time.time()
        message_plaintext, device_sent_message_plaintext, err = marshal_message(to, message)
        timings.marshal = time.time() - start
        if err is not None:
            return None, err

        node, _, err = prepare_message_node(
            client, to, id, message, [to, own_id.to_non_ad()],
            message_plaintext, device_sent_message_plaintext, timings, extra_params
        )
        if err is not None:
            return None, err

        start = time.time()
        data, err = client.send_node_and_get_data(node)
        timings.send = time.time() - start
        if err is not None:
            return None, Exception(f"failed to send message node: {err}")

        return data, None

    except Exception as e:
        return None, e


def get_type_from_message(msg: waE2E_pb2.Message) -> str:
    """
    Port of Go function getTypeFromMessage from client.go.

    Determines the high-level message type by recursively checking wrapped messages
    and categorizing into reaction, poll, media, or text types.

    Args:
        msg: Message protobuf to analyze

    Returns:
        String indicating the message type: "reaction", "poll", "media", or "text"
    """

    # Case 1: ViewOnceMessage - recurse on inner message
    if msg.view_once_message is not None:
        return get_type_from_message(msg.view_once_message.message)

    # Case 2: ViewOnceMessageV2 - recurse on inner message
    elif msg.view_once_message_v2 is not None:
        return get_type_from_message(msg.view_once_message_v2.message)

    # Case 3: ViewOnceMessageV2Extension - recurse on inner message
    elif msg.view_once_message_v2_extension is not None:
        return get_type_from_message(msg.view_once_message_v2_extension.message)

    # Case 4: LottieStickerMessage - recurse on inner message
    elif msg.lottie_sticker_message is not None:
        return get_type_from_message(msg.lottie_sticker_message.message)

    # Case 5: EphemeralMessage - recurse on inner message
    elif msg.ephemeral_message is not None:
        return get_type_from_message(msg.ephemeral_message.message)

    # Case 6: DocumentWithCaptionMessage - recurse on inner message
    elif msg.document_with_caption_message is not None:
        return get_type_from_message(msg.document_with_caption_message.message)

    # Case 7: Reaction messages (ReactionMessage or EncReactionMessage)
    elif (msg.reaction_message is not None or
          msg.enc_reaction_message is not None):
        return "reaction"

    # Case 8: Poll messages (PollCreationMessage or PollUpdateMessage)
    elif (msg.poll_creation_message is not None or
          msg.poll_update_message is not None):
        return "poll"

    # Case 9: Media message - check if has media type
    elif get_media_type_from_message(msg) != "":
        return "media"

    # Case 10: Text messages (Conversation, ExtendedTextMessage, or ProtocolMessage)
    elif (msg.conversation is not None or
          msg.extended_text_message is not None or
          msg.protocol_message is not None):
        return "text"

    # Default case - treat as text
    else:
        return "text"


def get_media_type_from_message(msg: waE2E_pb2.Message) -> str:
    """
    Port of Go function getMediaTypeFromMessage from client.go.

    Determines the media type string from a message by recursively checking wrapped messages
    and identifying specific media message types with special handling for audio/video variants.

    Args:
        msg: Message protobuf to analyze

    Returns:
        String indicating the media type, or empty string if no media type found
    """

    # Case 1: ViewOnceMessage - recurse on inner message
    if msg.view_once_message is not None:
        return get_media_type_from_message(msg.view_once_message.message)

    # Case 2: ViewOnceMessageV2 - recurse on inner message
    elif msg.view_once_message_v2 is not None:
        return get_media_type_from_message(msg.view_once_message_v2.message)

    # Case 3: ViewOnceMessageV2Extension - recurse on inner message
    elif msg.view_once_message_v2_extension is not None:
        return get_media_type_from_message(msg.view_once_message_v2_extension.message)

    # Case 4: LottieStickerMessage - recurse on inner message
    elif msg.lottie_sticker_message is not None:
        return get_media_type_from_message(msg.lottie_sticker_message.message)

    # Case 5: EphemeralMessage - recurse on inner message
    elif msg.ephemeral_message is not None:
        return get_media_type_from_message(msg.ephemeral_message.message)

    # Case 6: DocumentWithCaptionMessage - recurse on inner message
    elif msg.document_with_caption_message is not None:
        return get_media_type_from_message(msg.document_with_caption_message.message)

    # Case 7: ExtendedTextMessage with title (URL)
    elif (msg.extended_text_message is not None and
          msg.extended_text_message.title is not None):
        return "url"

    # Case 8: ImageMessage
    elif msg.image_message is not None:
        return "image"

    # Case 9: StickerMessage
    elif msg.sticker_message is not None:
        return "sticker"

    # Case 10: DocumentMessage
    elif msg.document_message is not None:
        return "document"

    # Case 11: AudioMessage - check for PTT vs regular audio
    elif msg.audio_message is not None:
        if msg.audio_message.ptt:
            return "ptt"
        else:
            return "audio"

    # Case 12: VideoMessage - check for GIF vs regular video
    elif msg.video_message is not None:
        if msg.video_message.gif_playback:
            return "gif"
        else:
            return "video"

    # Case 13: ContactMessage
    elif msg.contact_message is not None:
        return "vcard"

    # Case 14: ContactsArrayMessage
    elif msg.contacts_array_message is not None:
        return "contact_array"

    # Case 15: ListMessage
    elif msg.list_message is not None:
        return "list"

    # Case 16: ListResponseMessage
    elif msg.list_response_message is not None:
        return "list_response"

    # Case 17: ButtonsResponseMessage
    elif msg.buttons_response_message is not None:
        return "buttons_response"

    # Case 18: OrderMessage
    elif msg.order_message is not None:
        return "order"

    # Case 19: ProductMessage
    elif msg.product_message is not None:
        return "product"

    # Case 20: InteractiveResponseMessage
    elif msg.interactive_response_message is not None:
        return "native_flow_response"

    # Default case - no media type found
    else:
        return ""


def get_button_type_from_message(msg: waE2E_pb2.Message) -> str:
    """
    Port of Go function getButtonTypeFromMessage from client.go.

    Determines the button type string from a message by recursively checking wrapped messages
    and identifying specific button/interactive message types.

    Args:
        msg: Message protobuf to analyze

    Returns:
        String indicating the button type, or empty string if no button type found
    """

    # Case 1: ViewOnceMessage - recurse on inner message
    if msg.view_once_message is not None:
        return get_button_type_from_message(msg.view_once_message.message)

    # Case 2: ViewOnceMessageV2 - recurse on inner message
    elif msg.view_once_message_v2 is not None:
        return get_button_type_from_message(msg.view_once_message_v2.message)

    # Case 3: EphemeralMessage - recurse on inner message
    elif msg.ephemeral_message is not None:
        return get_button_type_from_message(msg.ephemeral_message.message)

    # Case 4: ButtonsMessage
    elif msg.buttons_message is not None:
        return "buttons"

    # Case 5: ButtonsResponseMessage
    elif msg.buttons_response_message is not None:
        return "buttons_response"

    # Case 6: ListMessage
    elif msg.list_message is not None:
        return "list"

    # Case 7: ListResponseMessage
    elif msg.list_response_message is not None:
        return "list_response"

    # Case 8: InteractiveResponseMessage
    elif msg.interactive_response_message is not None:
        return "interactive_response"

    # Default case - no button type found
    else:
        return ""


def get_button_attributes(msg: waE2E_pb2.Message) -> Attrs:
    """
    Port of Go function getButtonAttributes from client.go.

    Extracts button attributes from a message by recursively checking wrapped messages
    and extracting specific attributes for list messages.

    Args:
        msg: Message protobuf to analyze

    Returns:
        waBinary.Attrs dictionary containing button attributes
    """
    # TODO: Review waBinary.Attrs implementation

    # Case 1: ViewOnceMessage - recurse on inner message
    if msg.view_once_message is not None:
        return get_button_attributes(msg.view_once_message.message)

    # Case 2: ViewOnceMessageV2 - recurse on inner message
    elif msg.view_once_message_v2 is not None:
        return get_button_attributes(msg.view_once_message_v2.message)

    # Case 3: EphemeralMessage - recurse on inner message
    elif msg.ephemeral_message is not None:
        return get_button_attributes(msg.ephemeral_message.message)

    # Case 4: TemplateMessage - return empty attributes
    elif msg.template_message is not None:
        return Attrs({})

    # Case 5: ListMessage - return version and type attributes
    elif msg.list_message is not None:
        # Get the list type enum value and convert to lowercase string
        list_type_value = msg.list_message.list_type
        list_type_name = waE2E_pb2.ListMessage.ListType.Name(list_type_value)
        return Attrs({
            "v": "2",
            "type": list_type_name.lower(),
        })

    # Default case - return empty attributes
    else:
        return Attrs({})


def get_edit_attribute(msg: waE2E_pb2.Message) -> 'EditAttribute':
    """
    Port of Go function getEditAttribute from client.go.

    Determines the edit attribute type for a message based on its content,
    handling edited messages, protocol messages (revoke/edit), reactions, and keep-in-chat.

    Args:
        msg: Message protobuf to analyze

    Returns:
        EditAttribute enum value indicating the type of edit operation
    """
    # TODO: Review types.EditAttribute implementation
    # TODO: Review REMOVE_REACTION_TEXT constant implementation

    # Case 1: Edited message - recurse on the inner message
    if (msg.edited_message is not None and
        msg.edited_message.message is not None):
        return get_edit_attribute(msg.edited_message.message)

    # Case 2: Protocol message with key
    if (msg.protocol_message is not None and
        msg.protocol_message.key is not None):

        if msg.protocol_message.type == waE2E_pb2.ProtocolMessage.REVOKE:
            if msg.protocol_message.key.from_me:
                return EditAttribute.SENDER_REVOKE
            else:
                return EditAttribute.ADMIN_REVOKE

        elif msg.protocol_message.type == waE2E_pb2.ProtocolMessage.MESSAGE_EDIT:
            if msg.protocol_message.edited_message is not None:
                return EditAttribute.MESSAGE_EDIT

    # Case 3: Reaction message with remove text
    if (msg.reaction_message is not None and
        msg.reaction_message.text == REMOVE_REACTION_TEXT):
        return EditAttribute.SENDER_REVOKE

    # Case 4: Keep-in-chat message with undo operation
    if (msg.keep_in_chat_message is not None and
        msg.keep_in_chat_message.key is not None and
        msg.keep_in_chat_message.key.from_me and
        msg.keep_in_chat_message.keep_type == waE2E_pb2.KeepType.UNDO_KEEP_FOR_ALL):
        return EditAttribute.SENDER_REVOKE

    return EditAttribute.EMPTY


async def prepare_peer_message_node(
    client: 'Client',
    to: JID,
    id: MessageID,
    message: waE2E_pb2.Message,
    timings: MessageDebugTimings,
) -> Tuple[Optional[Node], Optional[Exception]]:
    """
    Port of Go method preparePeerMessageNode from client.go.

    Prepares a peer-to-peer message node by marshaling and encrypting the message
    for a single device, with optional device identity inclusion for prekey messages.

    Args:
        client:
        to: Target peer JID
        id: Message ID
        message: Message protobuf to send
        timings: Debug timing tracker

    Returns:
        Tuple containing (message_node, error)
    """
    # TODO: Review waBinary.Attrs implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review encrypt_message_for_device implementation
    # TODO: Review make_device_identity_node implementation

    attrs = Attrs({
        "id": id,
        "type": "text",
        "category": "peer",
        "to": to,
    })

    # Check for APP_STATE_SYNC_KEY_REQUEST to set high priority
    if (message.protocol_message is not None and
        message.protocol_message.type == waE2E_pb2.ProtocolMessage.APP_STATE_SYNC_KEY_REQUEST):
        attrs["push_priority"] = "high"

    start = time.time()
    try:
        plaintext = message.SerializeToString()
    except Exception as err:
        return None, Exception(f"failed to marshal message: {err}")
    timings.marshal = time.time() - start

    start = time.time()
    encrypted, is_pre_key, err = await encrypt_message_for_device(client, plaintext, to, None, None)
    timings.peer_encrypt = time.time() - start
    if err is not None:
        return None, Exception(f"failed to encrypt peer message for {to}: {err}")

    content = [encrypted]
    if is_pre_key and client.messenger_config is None:
        content.append(make_device_identity_node(client))

    message_node = Node(
        tag="message",
        attrs=attrs,
        content=content,
    )

    return message_node, None


def get_message_content(
    client: 'Client',
    base_node: Node,
    message: waE2E_pb2.Message,
    msg_attrs: Attrs,
    include_identity: bool,
    extra_params: NodeExtraParams,
) -> List[Node]:
    """
    Port of Go method getMessageContent from client.go.

    Builds the complete message content by combining the base node with optional
    identity, poll metadata, bot/meta nodes, and button information.

    Args:
        base_node: Base message node (usually participants node)
        message: Message protobuf containing message data
        msg_attrs: Message attributes dictionary
        include_identity: Whether to include device identity node
        extra_params: Extra parameters containing optional bot/meta nodes

    Returns:
        List of nodes forming the complete message content
    """
    # TODO: Review make_device_identity_node implementation
    # TODO: Review get_button_type_from_message implementation
    # TODO: Review get_button_attributes implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review waBinary.Attrs implementation

    content = [base_node]

    if include_identity:
        content.append(make_device_identity_node(client))

    if msg_attrs["type"] == "poll":
        poll_type = "creation"
        if message.poll_update_message is not None:
            poll_type = "vote"
        content.append(Node(
            tag="meta",
            attrs=Attrs({
                "polltype": poll_type,
            }),
        ))

    if extra_params.bot_node is not None:
        content.append(extra_params.bot_node)

    if extra_params.meta_node is not None:
        content.append(extra_params.meta_node)

    button_type = get_button_type_from_message(message)
    if button_type != "":
        content.append(Node(
            tag="biz",
            content=[Node(
                tag=button_type,
                attrs=get_button_attributes(message),
            )],
        ))

    return content


async def prepare_message_node(
    client: 'Client',
    to: JID,
    id: MessageID,
    message: waE2E_pb2.Message,
    participants: List[JID],
    plaintext: bytes,
    dsm_plaintext: Optional[bytes],
    timings: MessageDebugTimings,
    extra_params: NodeExtraParams,
) -> Tuple[Optional[Node], Optional[List[JID]], Optional[Exception]]:
    """
    Port of Go method prepareMessageNode from client.go.

    Prepares a message node by encrypting for all participant devices and building
    the complete message structure with proper attributes and content.

    Args:
        client:
        to: Target JID (group or individual)
        id: Message ID
        message: Message protobuf to send
        participants: List of participant JIDs
        plaintext: Message plaintext bytes
        dsm_plaintext: Device sent message plaintext bytes (optional)
        timings: Debug timing tracker
        extra_params: Extra parameters for node construction

    Returns:
        Tuple containing (message_node, all_devices, error)
    """
    # TODO: Review GetUserDevicesContext implementation
    # TODO: Review get_type_from_message implementation
    # TODO: Review get_media_type_from_message implementation
    # TODO: Review get_edit_attribute implementation
    # TODO: Review encrypt_message_for_devices implementation
    # TODO: Review get_message_content implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review waBinary.Attrs implementation
    # TODO: Review events.DecryptFailHide implementation

    start = time.time()
    all_devices, err = await get_user_devices_context(client, participants)
    timings.get_devices = time.time() - start
    if err is not None:
        return None, None, Exception(f"failed to get device list: {err}")

    msg_type = get_type_from_message(message)
    enc_attrs = Attrs({})

    # Only include encMediaType for 1:1 messages (groups don't have a device-sent message plaintext)
    enc_media_type = get_media_type_from_message(message)
    if dsm_plaintext is not None and enc_media_type != "":
        enc_attrs["mediatype"] = enc_media_type

    attrs = Attrs({
        "id": id,
        "type": msg_type,
        "to": to,
    })

    # TODO this is a very hacky hack for announcement group messages, why is it pn anyway?
    if extra_params.addressing_mode != "":
        attrs["addressing_mode"] = str(extra_params.addressing_mode)

    edit_attr = get_edit_attribute(message)
    if edit_attr != "":
        attrs["edit"] = str(edit_attr)
        enc_attrs["decrypt-fail"] = str(events.DecryptFailMode.HIDE)

    if msg_type == "reaction" or message.poll_update_message is not None:
        enc_attrs["decrypt-fail"] = str(events.DecryptFailMode.HIDE)

    start = time.time()
    participant_nodes, include_identity = await encrypt_message_for_devices(
        client, all_devices, id, plaintext, dsm_plaintext, enc_attrs,
    )
    timings.peer_encrypt = time.time() - start

    participant_node = Node(
        tag="participants",
        content=participant_nodes,
    )

    message_node = Node(
        tag="message",
        attrs=attrs,
        content=get_message_content(
            participant_node, message, attrs, include_identity, extra_params,
        ),
    )

    return message_node, all_devices, None


def marshal_message(to_jid: JID, message: waE2E_pb2.Message):
    """
    Marshal a message for sending over WhatsApp.

    Converts the protobuf message to bytes for transmission and creates
    device-specific message (DSM) plaintext if needed.

    Args:
        to_jid: Target JID
        message: waE2E.Message protobuf object

    Returns:
        tuple: (message_plaintext_bytes, dsm_plaintext_bytes, error)
               dsm_plaintext_bytes will be None if not needed
    """
    try:
        # Handle None message (e.g., for revoke operations)
        if message is None:
            return b"", None, None

        # Serialize the protobuf message to bytes
        try:
            message_bytes = message.SerializeToString()
        except Exception as e:
            return None, None, f"Failed to serialize message: {e}"

        # DSM (Device Specific Message) is only needed for certain scenarios
        # For now, we'll return None for DSM as it's not always required
        dsm_plaintext = None

        # In the Go implementation, DSM handling depends on various factors:
        # - Group messages may need DSM for sender key distribution
        # - Bot messages have special handling
        # - For most regular messages, DSM is not needed

        return message_bytes, dsm_plaintext, None

    except Exception as e:
        return None, None, f"Marshal message error: {e}"


def make_device_identity_node(client: 'Client') -> Node:
    """
    Port of Go method makeDeviceIdentityNode from client.go.

    Creates a device identity node for message sending.

    Args:
        client: The WhatsApp client instance

    Returns:
        Node containing the device identity

    Raises:
        Exception: If device identity marshaling fails
    """
    # TODO: Review Node implementation

    from google.protobuf import message as proto_message

    try:
        device_identity = proto_message.MessageToBytes(client.store.account)
    except Exception as e:
        raise Exception(f"failed to marshal device identity: {e}")

    return Node(
        tag="device-identity",
        content=device_identity
    )


async def encrypt_message_for_devices(
    client: 'Client',
    all_devices: List[JID],
    id: str,
    msg_plaintext: bytes,
    dsm_plaintext: Optional[bytes],
    enc_attrs: Attrs
) -> Tuple[List[Node], bool]:
    """
    Port of Go method encryptMessageForDevices from send.go.

    Encrypts a message for multiple devices, handling DSM messages for own devices,
    LID migration, and prekey retries.

    Args:
        client: The WhatsApp client instance
        ctx: Context for the operation
        all_devices: List of all target device JIDs
        id: Message ID for logging
        msg_plaintext: The main message plaintext
        dsm_plaintext: Optional DSM plaintext for own devices
        enc_attrs: Encryption attributes to apply to nodes

    Returns:
        Tuple containing:
        - List[waBinary.Node]: List of encrypted message nodes
        - bool: Whether identity should be included (if any prekey messages)
    """
    # TODO: Review Client.get_own_id implementation
    # TODO: Review Client.get_own_lid implementation
    own_jid = client.get_own_id()
    own_lid = client.get_own_lid()
    include_identity = False
    participant_nodes = []
    retry_devices = []
    retry_encryption_identities = []

    for jid in all_devices:
        plaintext = msg_plaintext
        if (jid.user == own_jid.user or jid.user == own_lid.user) and dsm_plaintext is not None:
            if jid == own_jid:
                continue
            plaintext = dsm_plaintext

        encryption_identity = jid
        if jid.server == DEFAULT_USER_SERVER:
            # TODO: Review Store.LIDs.get_lid_for_pn implementation
            try:
                lid_for_pn, err = client.store.lids.get_lid_for_pn(jid)
                if err:
                    logger.warning(f"Failed to get LID for {jid}: {err}")
                elif not lid_for_pn.is_empty():
                    # TODO: Review message.migrate_session_store implementation
                    await migrate_session_store(client, jid, lid_for_pn)
                    encryption_identity = lid_for_pn
            except Exception as e:
                logger.warning(f"Failed to get LID for {jid}: {e}")

        # TODO: Review Client.encrypt_message_for_device_and_wrap implementation
        encrypted, is_pre_key, err = await encrypt_message_for_device_and_wrap(
            client, plaintext, jid, encryption_identity, None, enc_attrs
        )

        if err and hasattr(err, '__class__') and 'NoSession' in err.__class__.__name__:
            retry_devices.append(jid)
            retry_encryption_identities.append(encryption_identity)
            continue
        elif err:
            # TODO return these errors if it's a fatal one (like context cancellation or database)
            logger.warning(f"Failed to encrypt {id} for {jid}: {err}")
            continue

        participant_nodes.append(encrypted)
        if is_pre_key:
            include_identity = True

    if len(retry_devices) > 0:
        # TODO: Review prekeys.fetch_pre_keys implementation
        bundles, err = fetch_pre_keys(client, retry_devices)
        if err:
            logger.warning(f"Failed to fetch prekeys for {retry_devices} to retry encryption: {err}")
        else:
            for i, jid in enumerate(retry_devices):
                resp = bundles.get(jid)
                if resp is None or resp.err:
                    logger.warning(f"Failed to fetch prekey for {jid}: {resp.err if resp else 'no response'}")
                    continue

                plaintext = msg_plaintext
                if (jid.user == own_jid.user or jid.user == own_lid.user) and dsm_plaintext is not None:
                    plaintext = dsm_plaintext

                encrypted, is_pre_key, err = await encrypt_message_for_device_and_wrap(
                    client, plaintext, jid, retry_encryption_identities[i], resp.bundle, enc_attrs
                )
                if err:
                    # TODO return these errors if it's a fatal one (like context cancellation or database)
                    logger.warning(f"Failed to encrypt {id} for {jid} (retry): {err}")
                    continue

                participant_nodes.append(encrypted)
                if is_pre_key:
                    include_identity = True

    return participant_nodes, include_identity


async def encrypt_message_for_device_and_wrap(
    client: 'Client',
    plaintext: bytes,
    wire_identity: JID,
    encryption_identity: JID,
    bundle: Optional[prekeys.PreKeyBundle],
    enc_attrs: Attrs
) -> Tuple[Optional[Node], bool, Optional[Exception]]:
    """
    Port of Go method encryptMessageForDeviceAndWrap from send.go.

    Encrypts a message for a specific device and wraps it in a "to" node with the wire identity.
    This is a wrapper around encryptMessageForDevice that adds the proper XML structure.

    Args:
        client: The WhatsApp client instance
        ctx: Context for the operation
        plaintext: The message plaintext to encrypt
        wire_identity: The JID to use in the "to" node attributes
        encryption_identity: The JID to use for actual encryption
        bundle: Optional prekey bundle for session creation
        enc_attrs: Encryption attributes to apply

    Returns:
        Tuple containing:
        - Optional[waBinary.Node]: The wrapped encrypted node (None on error)
        - bool: Whether device identity should be included
        - Optional[Exception]: Any error that occurred
    """
    # TODO: Review Client.encrypt_message_for_device implementation
    node, include_device_identity, err = await encrypt_message_for_device(
        client ,plaintext, encryption_identity, bundle, enc_attrs
    )

    if err is not None:
        return None, False, err

    wrapped_node = Node(
        tag="to",
        attrs={"jid": wire_identity},
        content=[node]
    )

    return wrapped_node, include_device_identity, None


def copy_attrs(from_: Attrs, to: Attrs) -> None:
    """
    Port of Go function copyAttrs from client.go.

    Copies all key-value pairs from one Attrs to another.

    Args:
        from_: Source attributes to copy from
        to: Target attributes to copy to
    """
    # TODO: Review Attrs implementation

    for k, v in from_.items():
        to[k] = v


async def encrypt_message_for_device(
    client: 'Client',
    plaintext: bytes,
    to: JID,
    bundle: Optional[prekeys.PreKeyBundle],
    extra_attrs: Attrs
) -> Tuple[Optional[Node], bool, Optional[Exception]]:
    """
    Port of Go method encryptMessageForDevice from send.go.

    Encrypts a message for a specific device using the Signal protocol.
    Handles session creation, prekey bundle processing, and message encryption.

    Args:
        client: The WhatsApp client instance
        plaintext: The message plaintext to encrypt
        to: The recipient device JID
        bundle: Optional prekey bundle for session creation
        extra_attrs: Additional attributes to apply to the encrypted node

    Returns:
        Tuple containing:
        - Optional[waBinary.Node]: The encrypted message node (None on error)
        - bool: Whether device identity should be included
        - Optional[Exception]: Any error that occurred
    """
    # TODO: Review session implementation
    # TODO: Review prekey.Bundle implementation
    # TODO: Review pb_serializer implementation
    # TODO: Review UntrustedIdentityError implementation
    # TODO: Review ErrNoSession implementation
    # TODO: Review protocol.PREKEY_TYPE implementation

    from signal_protocol import session, UntrustedIdentityError, protocol

    try:
        builder = session.new_builder_from_signal(client.store, to.signal_address(), pb_serializer)

        if bundle is not None:
            logger.debug(f"Processing prekey bundle for {to}")
            err = builder.process_bundle(ctx, bundle)

            if client.auto_trust_identity and isinstance(err, UntrustedIdentityError):
                logger.warning(
                    f"Got {err} error while trying to process prekey bundle for {to}, "
                    f"clearing stored identity and retrying"
                )
                err = clear_untrusted_identity(client, to)
                if err is not None:
                    return None, False, Exception(f"failed to clear untrusted identity: {err}")
                err = builder.process_bundle(ctx, bundle)

            if err is not None:
                return None, False, Exception(f"failed to process prekey bundle: {err}")
        else:
            contains, err = contains_session(client.store, to.signal_address())
            if err is not None:
                return None, False, err
            elif not contains:
                return None, False, ErrNoSession

        cipher = session.new_cipher(builder, to.signal_address())
        ciphertext, err = cipher.encrypt(ctx, pad_message(plaintext))
        if err is not None:
            return None, False, Exception(f"cipher encryption failed: {err}")

        enc_attrs = {
            "v": "2",
            "type": "msg"
        }

        if ciphertext.type() == protocol.PREKEY_TYPE:
            enc_attrs["type"] = "pkmsg"

        copy_attrs(extra_attrs, enc_attrs)

        include_device_identity = (enc_attrs["type"] == "pkmsg" and
                                   client.messenger_config is None)

        encrypted_node = Node(
            tag="enc",
            attrs=enc_attrs,
            content=ciphertext.serialize()
        )

        return encrypted_node, include_device_identity, None

    except Exception as e:
        return None, False, e


# EditWindow specifies how long a message can be edited for after it was sent.
EDIT_WINDOW = timedelta(minutes=20)

# Disappearing timer constants
DISAPPEARING_TIMER_OFF = timedelta(0)
DISAPPEARING_TIMER_24_HOURS = timedelta(hours=24)
DISAPPEARING_TIMER_7_DAYS = timedelta(days=7)
DISAPPEARING_TIMER_90_DAYS = timedelta(days=90)


