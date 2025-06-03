"""
Message handling for PyMeow.

Port of whatsmeow/message.go - handles encrypted and plaintext messages.
"""

import hashlib
import logging
import time
from datetime import datetime
from typing import Optional, Tuple

from .binary.node import Node, AttrGetter
from .exceptions import ErrNotLoggedIn
from .msgsecret import decrypt_bot_message
from .types import JID, MessageInfo
from .types.events import (
    Message as MessageEvent,
    UndecryptableMessage,
    HistorySync,
    NewsletterMessageMeta
)
from .types.message import MessageSource, AddressingMode, MessageID
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2

logger = logging.getLogger(__name__)

# Constants
EVENT_ALREADY_PROCESSED = "event was already processed"
CHECK_PADDING = True
REQUEST_FROM_PHONE_DELAY = 3600  # 1 hour in seconds

# Encryption secret constants
ENC_SECRET_POLL_VOTE = "poll_vote_enc"
ENC_SECRET_REACTION = "reaction_enc"
ENC_SECRET_COMMENT = "comment_enc"
ENC_SECRET_REPORT_TOKEN = "report_token_enc"
ENC_SECRET_EVENT_RESPONSE = "event_response_enc"
ENC_SECRET_EVENT_EDIT = "event_edit_enc"
ENC_SECRET_BOT_MSG = "bot_msg_enc"

pb_serializer = None  # Will be set when store is initialized

# Define EventAlreadyProcessed locally as it's defined in the Go code
class EventAlreadyProcessed(Exception):
    """Error indicating that an event was already processed."""
    def __init__(self, message="event was already processed"):
        super().__init__(message)


def parse_message_source(node: Node, require_participant: bool = True, client_id: Optional[JID] = None, client_lid: Optional[JID] = None) -> MessageSource:
    """Parse message source information from a binary node.

    Args:
        node: The binary node containing message information
        require_participant: Whether to require participant attribute for group messages
        client_id: The client's JID
        client_lid: The client's LID

    Returns:
        MessageSource object with parsed information

    Raises:
        NotLoggedInError: If client_id is empty
    """
    if not client_id or client_id.is_empty():
        raise ErrNotLoggedIn("Client ID is required to parse message source")

    ag = AttrGetter(node.attrs)
    from_jid = ag.jid("from")
    source = MessageSource()
    source.addressing_mode = AddressingMode(ag.optional_string("addressing_mode") or "")

    if from_jid.server in ["g.us", "broadcast"]:  # Group or broadcast
        source.is_group = True
        source.chat = from_jid
        if require_participant:
            source.sender = ag.jid("participant")
        else:
            source.sender = ag.optional_jid_or_empty("participant")

        if source.addressing_mode == AddressingMode.LID:
            source.sender_alt = ag.optional_jid_or_empty("participant_pn")
        else:
            source.sender_alt = ag.optional_jid_or_empty("participant_lid")

        if source.sender.user == client_id.user or (client_lid and source.sender.user == client_lid.user):
            source.is_from_me = True

        if from_jid.server == "broadcast":
            source.broadcast_list_owner = ag.optional_jid_or_empty("recipient")

    elif from_jid.server == "newsletter":
        source.chat = from_jid
        source.sender = from_jid
        # TODO: IsFromMe for newsletters?

    elif from_jid.user == client_id.user or (client_lid and from_jid.user == client_lid.user):
        source.is_from_me = True
        source.sender = from_jid
        recipient = ag.optional_jid("recipient")
        if recipient:
            source.chat = recipient
        else:
            source.chat = from_jid.to_non_ad()

        if source.addressing_mode == AddressingMode.LID:
            source.recipient_alt = ag.optional_jid_or_empty("peer_recipient_pn")
        else:
            source.recipient_alt = ag.optional_jid_or_empty("peer_recipient_lid")

    elif from_jid.is_bot():
        source.sender = from_jid
        meta = node.get_child_by_tag("meta")
        if meta:
            meta_ag = AttrGetter(meta.attrs)
            target_chat_jid = meta_ag.optional_jid("target_chat_jid")
            if target_chat_jid:
                source.chat = target_chat_jid.to_non_ad()
            else:
                source.chat = from_jid
        else:
            source.chat = from_jid
    else:
        source.chat = from_jid.to_non_ad()
        source.sender = from_jid
        if source.addressing_mode == AddressingMode.LID:
            source.sender_alt = ag.optional_jid_or_empty("sender_pn")
        else:
            source.sender_alt = ag.optional_jid_or_empty("sender_lid")

    if not source.sender_alt.is_empty() and source.sender_alt.device == 0:
        source.sender_alt.device = source.sender.device

    ag.raise_on_error()
    return source


def parse_msg_bot_info(node: Node) -> dict:
    """Parse bot information from a message node.

    Args:
        node: The binary node containing bot information

    Returns:
        Dictionary with bot information
    """
    bot_node = node.get_child_by_tag("bot")
    if not bot_node:
        return {}

    ag = AttrGetter(bot_node.attrs)
    bot_info = {
        "edit_type": ag.string("edit") if ag.has_attr("edit") else None
    }

    if bot_info["edit_type"] in ["inner", "last"]:
        bot_info["edit_target_id"] = MessageID(ag.string("edit_target_id"))
        bot_info["edit_sender_timestamp_ms"] = ag.unix_milli("sender_timestamp_ms")

    ag.raise_on_error()
    return bot_info


def parse_msg_meta_info(node: Node) -> dict:
    """Parse meta information from a message node.

    Args:
        node: The binary node containing meta information

    Returns:
        Dictionary with meta information
    """
    meta_node = node.get_child_by_tag("meta")
    if not meta_node:
        return {}

    ag = AttrGetter(meta_node.attrs)
    meta_info = {
        "target_id": MessageID(ag.optional_string("target_id")) if ag.has_attr("target_id") else None,
        "target_sender": ag.optional_jid_or_empty("target_sender_jid"),
        "thread_message_id": MessageID(ag.optional_string("thread_msg_id")) if ag.has_attr("thread_msg_id") else None,
        "thread_message_sender_jid": ag.optional_jid_or_empty("thread_msg_sender_jid")
    }

    if ag.has_attr("deprecated_lid_session"):
        meta_info["deprecated_lid_session"] = ag.get_bool("deprecated_lid_session")
    else:
        meta_info["deprecated_lid_session"] = None

    ag.raise_on_error()
    return meta_info


def parse_message_info(node: Node, client_id: JID, client_lid: Optional[JID] = None) -> MessageInfo:
    """Parse complete message information from a binary node.

    Args:
        node: The binary node containing message information
        client_id: The client's JID
        client_lid: The client's LID (optional)

    Returns:
        MessageInfo object with parsed information
    """
    source = parse_message_source(node, True, client_id, client_lid)

    ag = AttrGetter(node.attrs)
    info = MessageInfo()
    info.message_source = source
    info.id = MessageID(ag.string("id"))
    info.server_id = ag.optional_int("server_id")
    info.timestamp = ag.unix_time("t")
    info.push_name = ag.optional_string("notify") or ""
    info.category = ag.optional_string("category") or ""
    info.type = ag.optional_string("type") or ""
    info.edit = ag.optional_string("edit") or ""

    ag.raise_on_error()

    # Parse child nodes
    for child in node.children:
        if child.tag == "multicast":
            info.multicast = True
        elif child.tag == "verified_name":
            # TODO: Parse verified name
            info.verified_name = child
        elif child.tag == "bot":
            info.msg_bot_info = parse_msg_bot_info(node)
        elif child.tag == "meta":
            info.msg_meta_info = parse_msg_meta_info(node)
        elif child.tag == "franking":
            # TODO: Handle franking
            pass
        elif child.tag == "trace":
            # TODO: Handle trace
            pass
        else:
            # Check for media type
            if "mediatype" in child.attrs:
                info.media_type = child.attrs["mediatype"]

    return info


async def handle_encrypted_message(client, node: Node):
    """Handle an encrypted message node.

    Args:
        client: The WhatsApp client instance
        node: The encrypted message node
    """
    try:
        info = parse_message_info(node, client.get_own_id(), client.get_own_lid())
    except Exception as e:
        logger.warning(f"Failed to parse message: {e}")
        return

    # Store LID/PN mappings
    if not info.sender_alt.is_empty():
        await client.store_lid_pn_mapping(info.sender_alt, info.sender)
    elif not info.recipient_alt.is_empty():
        await client.store_lid_pn_mapping(info.recipient_alt, info.chat)

    # Update business name if available
    if info.verified_name and hasattr(info.verified_name, 'details'):
        verified_name = getattr(info.verified_name.details, 'verified_name', '')
        if verified_name:
            client.schedule_task(client.update_business_name(info.sender, info, verified_name))

    # Update push name if available
    if info.push_name and info.push_name != "-":
        client.schedule_task(client.update_push_name(info.sender, info, info.push_name))

    # Handle the message based on sender server
    if info.sender.server == "newsletter":
        await handle_plaintext_message(client, info, node)
    else:
        await decrypt_messages(client, info, node)


async def handle_plaintext_message(client, info: MessageInfo, node: Node):
    """Handle a plaintext message (typically from newsletters).

    Args:
        client: The WhatsApp client instance
        info: Message information
        node: The message node
    """
    plaintext_node = node.get_optional_child_by_tag("plaintext")
    if not plaintext_node:
        return

    if not isinstance(plaintext_node.content, bytes):
        logger.warning(f"Plaintext message from {info.source_string()} doesn't have byte content")
        return

    try:
        msg = waE2E_pb2.Message()
        msg.ParseFromString(plaintext_node.content)
    except Exception as e:
        logger.warning(f"Error unmarshaling plaintext message from {info.source_string()}: {e}")
        return

    await store_message_secret(client, info, msg)

    evt = MessageEvent(info=info, raw_message=msg)

    # Check for newsletter metadata
    meta_node = node.get_optional_child_by_tag("meta")
    if meta_node:
        meta_ag = AttrGetter(meta_node.attrs)
        evt.newsletter_meta = NewsletterMessageMeta(
            edit_ts=meta_ag.unix_milli("msg_edit_t"),
            original_ts=meta_ag.unix_time("original_msg_t")
        )

    client.dispatch_event(evt.unwrap_raw())


def migrate_session_store(client, pn: JID, lid: JID):
    """Migrate session store from phone number to LID.

    Args:
        client: The WhatsApp client instance
        pn: Phone number JID
        lid: LID JID
    """
    try:
        client.store.sessions.migrate_pn_to_lid(pn, lid)
    except Exception as e:
        logger.error(f"Failed to migrate signal store from {pn} to {lid}: {e}")


async def decrypt_messages(client, info: MessageInfo, node: Node):
    """Decrypt encrypted messages from a node.

    Args:
        client: The WhatsApp client instance
        info: Message information
        node: The message node containing encrypted content
    """
    # Check for unavailable message
    unavailable_node = node.get_optional_child_by_tag("unavailable")
    enc_nodes = node.get_children_by_tag("enc")

    if unavailable_node and not enc_nodes:
        u_type = unavailable_node.attrs.get("type", "")
        logger.warning(f"Unavailable message {info.id} from {info.source_string()} (type: {u_type})")
        client.schedule_task(delayed_request_message_from_phone(client, info))
        client.dispatch_event(UndecryptableMessage(
            info=info,
            is_unavailable=True,
            unavailable_type=u_type
        ))
        return

    logger.debug(f"Decrypting message from {info.source_string()}")
    handled = False
    contains_direct_msg = False
    sender_encryption_jid = info.sender

    # Handle LID migration
    if info.sender.server == "s.whatsapp.net" and not info.sender.is_bot():
        if info.sender_alt.server == "lid":
            sender_encryption_jid = info.sender_alt
            migrate_session_store(client, info.sender, info.sender_alt)
        else:
            try:
                lid = await client.store.lids.get_lid_for_pn(info.sender)
                if not lid.is_empty():
                    migrate_session_store(client, info.sender, lid)
                    sender_encryption_jid = lid
                    info.sender_alt = lid
                else:
                    logger.warning(f"No LID found for {info.sender}")
            except Exception as e:
                logger.error(f"Failed to get LID for {info.sender}: {e}")

    for child in node.children:
        if child.tag != "enc":
            continue

        ag = AttrGetter(child.attrs)
        enc_type = ag.optional_string("type")
        if not enc_type:
            continue

        decrypted = None
        ciphertext_hash = None
        error = None

        try:
            if enc_type in ["pkmsg", "msg"]:
                decrypted, ciphertext_hash = await decrypt_dm(
                    client, child, sender_encryption_jid,
                    enc_type == "pkmsg", info.timestamp
                )
                contains_direct_msg = True
            elif info.is_group and enc_type == "skmsg":
                decrypted, ciphertext_hash = await decrypt_group_msg(
                    client, child, sender_encryption_jid, info.chat, info.timestamp
                )
            elif enc_type == "msmsg" and info.sender.is_bot():
                decrypted = await decrypt_bot_message_secret(
                    client, child, info
                )
            else:
                logger.warning(f"Unhandled encrypted message (type {enc_type}) from {info.source_string()}")
                continue

        except Exception as e:
            error = e

        if isinstance(error, EventAlreadyProcessed):
            logger.debug(f"Ignoring message {info.id} from {info.source_string()}: {error}")
            return
        elif error:
            logger.warning(f"Error decrypting message from {info.source_string()}: {error}")
            is_unavailable = (enc_type == "skmsg" and not contains_direct_msg and
                            "no sender key" in str(error).lower())
            if enc_type != "msmsg":
                client.schedule_task(send_retry_receipt(client, node, info, is_unavailable))
            client.dispatch_event(UndecryptableMessage(
                info=info,
                is_unavailable=is_unavailable,
                decrypt_fail_mode=ag.optional_string("decrypt-fail")
            ))
            return

        retry_count = ag.optional_int("count")
        client.cancel_delayed_request_from_phone(info.id)

        # Parse decrypted message
        version = ag.int("v")
        if version == 2:
            try:
                msg = waE2E_pb2.Message()
                msg.ParseFromString(decrypted)
                await handle_decrypted_message(client, info, msg, retry_count)
                handled = True
            except Exception as e:
                logger.warning(f"Error unmarshaling decrypted message from {info.source_string()}: {e}")
                continue
        elif version == 3:
            handled = await handle_decrypted_armadillo(client, info, decrypted, retry_count)
        else:
            logger.warning(f"Unknown version {version} in decrypted message from {info.source_string()}")

        # Clean up event buffer if enabled
        if ciphertext_hash and client.enable_decrypted_event_buffer:
            try:
                await client.store.event_buffer.clear_buffered_event_plaintext(ciphertext_hash)
                logger.debug(f"Deleted event plaintext from buffer")

                # Periodic cleanup
                if time.time() - client.last_decrypted_buffer_clear > 12 * 3600:  # 12 hours
                    client.last_decrypted_buffer_clear = time.time()
                    client.schedule_task(client.store.event_buffer.delete_old_buffered_hashes())
            except Exception as e:
                logger.error(f"Failed to clear buffered event plaintext: {e}")

    if handled:
        client.schedule_task(client.send_message_receipt(info))


async def decrypt_bot_message_secret(client, child: Node, info: MessageInfo) -> bytes:
    """Decrypt a bot message secret.

    Args:
        client: The WhatsApp client instance
        child: The encrypted node
        info: Message information

    Returns:
        Decrypted message bytes
    """
    target_sender_jid = info.msg_meta_info.get("target_sender", JID())
    message_secret_sender_jid = target_sender_jid

    if not target_sender_jid.user:
        if info.sender.server == "bot":
            target_sender_jid = client.get_own_lid()
        else:
            target_sender_jid = client.get_own_id()
        message_secret_sender_jid = client.get_own_id()

    # Determine message ID for decryption
    if info.msg_bot_info.get("edit_type") in ["inner", "last"]:
        decrypt_message_id = info.msg_bot_info["edit_target_id"]
    else:
        decrypt_message_id = info.id

    # Get message secret
    target_id = info.msg_meta_info.get("target_id")
    message_secret = await client.store.msg_secrets.get_message_secret(
        info.chat, message_secret_sender_jid, target_id
    )

    if not message_secret:
        raise Exception(f"Message secret for {target_id} not found")

    # Parse MessageSecretMessage
    ms_msg = waE2E_pb2.MessageSecretMessage()
    ms_msg.ParseFromString(child.content)

    return await decrypt_bot_message(
        client, message_secret, ms_msg, decrypt_message_id, target_sender_jid, info
    )


async def store_message_secret(client, info: MessageInfo, msg):
    """Store message secret for future decryption.

    Args:
        client: The WhatsApp client instance
        info: Message information
        msg: The message protobuf
    """
    # This would store secrets for bot message decryption
    # Implementation depends on the specific message secret storage system
    pass


async def handle_decrypted_message(client, info: MessageInfo, msg, retry_count: int):
    """Handle a decrypted message.

    Args:
        client: The WhatsApp client instance
        info: Message information
        msg: Decrypted message protobuf
        retry_count: Number of retry attempts
    """
    await store_message_secret(client, info, msg)

    evt = MessageEvent(info=info, raw_message=msg)
    client.dispatch_event(evt.unwrap_raw())


async def handle_decrypted_armadillo(client, info: MessageInfo, decrypted: bytes, retry_count: int) -> bool:
    """Handle a decrypted armadillo message.

    Args:
        client: The WhatsApp client instance
        info: Message information
        decrypted: Decrypted message bytes
        retry_count: Number of retry attempts

    Returns:
        True if handled successfully
    """
    # TODO: Implement armadillo message handling
    logger.warning(f"Armadillo message handling not implemented for {info.source_string()}")
    return False


async def decrypt_dm(client, child: Node, from_jid: JID, is_pre_key: bool, server_ts: datetime) -> Tuple[bytes, bytes]:
    """Decrypt a direct message.

    Args:
        client: The WhatsApp client instance
        child: The encrypted node
        from_jid: Sender JID
        is_pre_key: Whether this is a prekey message
        server_ts: Server timestamp

    Returns:
        Tuple of (decrypted_bytes, ciphertext_hash)
    """
    content = child.content
    if not isinstance(content, bytes):
        raise ValueError("Message content is not a byte slice")

    # Use signal protocol for decryption
    address = from_jid.signal_address()

    if is_pre_key:
        # Handle prekey message
        plaintext = await client.signal_store.decrypt_prekey_message(address, content)
    else:
        # Handle normal message
        plaintext = await client.signal_store.decrypt_message(address, content)

    # Unpad the message
    version = AttrGetter(child.attrs).int("v")
    plaintext = unpad_message(plaintext, version)

    # Calculate ciphertext hash for buffer management
    ciphertext_hash = hashlib.sha256(content).digest()

    return plaintext, ciphertext_hash


async def decrypt_group_msg(client, child: Node, from_jid: JID, chat: JID, server_ts: datetime) -> Tuple[bytes, bytes]:
    """Decrypt a group message.

    Args:
        client: The WhatsApp client instance
        child: The encrypted node
        from_jid: Sender JID
        chat: Group chat JID
        server_ts: Server timestamp

    Returns:
        Tuple of (decrypted_bytes, ciphertext_hash)
    """
    content = child.content
    if not isinstance(content, bytes):
        raise ValueError("Message content is not a byte slice")

    # Use signal protocol for group decryption
    sender_key_name = f"{chat}::{from_jid.signal_address()}"
    plaintext = await client.signal_store.decrypt_sender_key_message(sender_key_name, content)

    # Unpad the message
    version = AttrGetter(child.attrs).int("v")
    plaintext = unpad_message(plaintext, version)

    # Calculate ciphertext hash for buffer management
    ciphertext_hash = hashlib.sha256(content).digest()

    return plaintext, ciphertext_hash


async def send_retry_receipt(client, node: Node, info: MessageInfo, is_unavailable: bool):
    """Send a retry receipt for a failed decryption.

    Args:
        client: The WhatsApp client instance
        node: The original message node
        info: Message information
        is_unavailable: Whether the message is unavailable
    """
    # TODO: Implement retry receipt sending
    logger.debug(f"Sending retry receipt for {info.id} from {info.source_string()}")


async def delayed_request_message_from_phone(client, info: MessageInfo):
    """Request a message from phone after a delay.

    Args:
        client: The WhatsApp client instance
        info: Message information
    """
    await client.schedule_delayed_task(
        REQUEST_FROM_PHONE_DELAY,
        client.request_message_from_phone,
        info
    )


def is_valid_padding(plaintext: bytes) -> bool:
    """Check if message padding is valid.

    Args:
        plaintext: The message bytes to check

    Returns:
        True if padding is valid
    """
    if not plaintext:
        return False

    last_byte = plaintext[-1]
    expected_padding = bytes([last_byte] * last_byte)
    return plaintext.endswith(expected_padding)


def unpad_message(plaintext: bytes, version: int) -> bytes:
    """Remove padding from a decrypted message.

    Args:
        plaintext: The padded message bytes
        version: Protocol version

    Returns:
        Unpadded message bytes

    Raises:
        ValueError: If padding is invalid
    """
    if version == 3:
        return plaintext
    elif not plaintext:
        raise ValueError("Plaintext is empty")
    elif CHECK_PADDING and not is_valid_padding(plaintext):
        raise ValueError("Plaintext doesn't have expected padding")
    else:
        padding_length = plaintext[-1]
        return plaintext[:-padding_length]


def pad_message(plaintext: bytes) -> bytes:
    """Add padding to a message before encryption.

    Args:
        plaintext: The message bytes to pad

    Returns:
        Padded message bytes
    """
    import os
    pad_byte = os.urandom(1)[0] & 0xf
    if pad_byte == 0:
        pad_byte = 0xf

    padding = bytes([pad_byte] * pad_byte)
    return plaintext + padding
