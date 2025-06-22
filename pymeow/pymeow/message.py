"""
Message handling for PyMeow.

Port of whatsmeow/message.go - handles encrypted and plaintext messages.
"""

import asyncio
import hashlib
import logging
import os
import traceback
import zlib
from datetime import datetime
from typing import TYPE_CHECKING, Awaitable, Callable, Iterable, List, Optional, Tuple

import signal_protocol
from signal_protocol.group_cipher import process_sender_key_distribution_message

from . import receipt
from .appstate.keys import ALL_PATCH_NAMES
from .armadillomessage import handle_decrypted_armadillo
from .binary.attrs import Attrs
from .datatypes.jid import (
    BOT_SERVER,
    BROADCAST_SERVER,
    DEFAULT_USER_SERVER,
    EMPTY_JID,
    GROUP_SERVER,
    HIDDEN_USER_SERVER,
    LEGACY_USER_SERVER,
    NEWSLETTER_SERVER,
)
from .datatypes.message import (
    AddressingMode,
    BotEditType,
    EditAttribute,
    MessageID,
    MessageServerID,
    MessageSource,
    MsgBotInfo,
    MsgMetaInfo,
)
from .download import download
from .exceptions import ErrNotLoggedIn
from .generated.waE2E import WAWebProtobufsE2E_pb2
from .generated.waE2E.WAWebProtobufsE2E_pb2 import HistorySyncNotification
from .generated.waHistorySync import WAWebProtobufsHistorySync_pb2
from .generated.waWeb import WAWebProtobufsWeb_pb2
from .msgsecret import decrypt_bot_message
from .receipt import send_message_receipt
from .store import store
from .user import handle_historical_push_names, parse_verified_name_content, update_business_name, update_push_name

if TYPE_CHECKING:
    from .datatypes import JID, MessageInfo, ReceiptType, events

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

if TYPE_CHECKING:
    from .binary.node import Node
    from .client import Client


# Define EventAlreadyProcessed locally as it's defined in the Go code
class EventAlreadyProcessed(Exception):
    """Error indicating that an event was already processed."""

    def __init__(self, message: str = "event was already processed"):
        super().__init__(message)


async def handle_encrypted_message(client: "Client", node: "Node") -> None:
    """
    Port of Go method handleEncryptedMessage from client.go.

    Handles an encrypted message node by parsing message info, storing mappings,
    updating names, and either handling as plaintext or decrypting based on sender server.

    Args:
        client: The WhatsApp client instance
        node: The encrypted message node
    """
    # TODO: Review parse_message_info implementation
    # TODO: Review store_lid_pn_mapping implementation
    # TODO: Review update_business_name implementation
    # TODO: Review update_push_name implementation
    # TODO: Review maybe_deferred_ack implementation
    # TODO: Review handle_plaintext_message implementation
    # TODO: Review decrypt_messages implementation
    # TODO: Review types.NewsletterServer implementation

    info = await parse_message_info(client, node)
    if not info.sender_alt.is_empty():
        await client.store_lid_pn_mapping(info.sender_alt, info.sender)
    elif not info.recipient_alt.is_empty():
        await client.store_lid_pn_mapping(info.recipient_alt, info.chat)

    if info.verified_name is not None and len(info.verified_name.details.get_verified_name()) > 0:
        # Go goroutine equivalent - async task

        await update_business_name(client, info.sender, info, info.verified_name.details.get_verified_name())

    if len(info.push_name) > 0 and info.push_name != "-":
        # Go goroutine equivalent - async task
        await update_push_name(client, info.sender, info, info.push_name)

    try:
        if info.sender.server == NEWSLETTER_SERVER:
            await handle_plaintext_message(client, info, node)
        else:
            await decrypt_messages(client, info, node)
    finally:
        client.create_task(receipt.send_ack(client, node))


async def parse_message_source(client: "Client", node: "Node", require_participant: bool) -> "MessageSource":
    """
    Port of Go method parseMessageSource from client.go.

    Parses message source information from a binary node including chat, sender,
    addressing mode, and other metadata based on message type.

    Args:
        client: The WhatsApp client instance
        node: The binary node containing message information
        require_participant: Whether to require participant attribute for group messages

    Returns:
        MessageSource object
    Raises:
        ErrNotLoggedIn
        Exception
    """
    # TODO: Review MessageSource implementation
    # TODO: Review get_own_id implementation
    # TODO: Review Store.get_lid implementation
    # TODO: Review AttrGetter implementation
    # TODO: Review types.GroupServer implementation
    # TODO: Review types.BroadcastServer implementation
    # TODO: Review types.NewsletterServer implementation
    # TODO: Review types.AddressingMode implementation
    # TODO: Review types.AddressingModeLID implementation
    # TODO: Review ErrNotLoggedIn implementation
    from .datatypes import JID

    source = MessageSource()

    client_id = client.get_own_id()
    client_lid = client.store.get_lid()

    if client_id.is_empty():
        raise ErrNotLoggedIn

    ag = node.attr_getter()
    from_jid = ag.jid("from")
    source.addressing_mode = AddressingMode(ag.optional_string("addressing_mode"))

    if from_jid.server == GROUP_SERVER or from_jid.server == BROADCAST_SERVER:
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

        if source.sender.user == client_id.user or source.sender.user == client_lid.user:
            source.is_from_me = True

        if from_jid.server == BROADCAST_SERVER:
            source.broadcast_list_owner = ag.optional_jid_or_empty("recipient")

    elif from_jid.server == NEWSLETTER_SERVER:
        source.chat = from_jid
        source.sender = from_jid
        # TODO IsFromMe?

    elif from_jid.user == client_id.user or from_jid.user == client_lid.user:
        source.is_from_me = True
        source.sender = from_jid
        recipient = ag.optional_jid("recipient")
        if recipient is not None:
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
        ag = meta.attr_getter()
        target_chat_jid = ag.optional_jid("target_chat_jid")
        if target_chat_jid is not None:
            source.chat = target_chat_jid.to_non_ad()
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
        # Create a new JID with the updated device
        source.sender_alt = JID(
            user=source.sender_alt.user, server=source.sender_alt.server, device=source.sender.device
        )

    err = ag.error()
    if err is not None:
        raise err
    return source


def parse_msg_bot_info(node: "Node") -> "MsgBotInfo":
    """
    Port of Go method parseMsgBotInfo from message.go.

    Parses bot information from a message node including edit type,
    target ID, and sender timestamp for bot messages.

    Args:
        node: The binary node containing message information

    Returns:
        MsgBotInfo object
    Raises:
        Exception: If the message is not a bot message
    """
    # TODO: Review MsgBotInfo implementation
    # TODO: Review BotEditType implementation
    # TODO: Review MessageID implementation
    # TODO: Review types.EditTypeInner implementation
    # TODO: Review types.EditTypeLast implementation
    # TODO: Review AttrGetter implementation

    bot_info = MsgBotInfo()

    bot_node = node.get_child_by_tag("bot")

    ag = bot_node.attr_getter()
    bot_info.edit_type = BotEditType(ag.string("edit"))

    if bot_info.edit_type == BotEditType.INNER or bot_info.edit_type == BotEditType.LAST:
        bot_info.edit_target_id = MessageID(ag.string("edit_target_id"))
        bot_info.edit_sender_timestamp_ms = ag.unix_milli("sender_timestamp_ms")

    err = ag.error()
    if err is not None:
        raise err
    return bot_info


def parse_msg_meta_info(node: "Node") -> Tuple[MsgMetaInfo, Optional[Exception]]:
    """
    Port of Go method parseMsgMetaInfo from message.go.

    Parses meta information from a message node including target ID,
    target sender, thread information, and deprecated LID session flag.

    Args:
        node: The binary node containing message information

    Returns:
        Tuple containing (MsgMetaInfo object, error or None)
    """
    # TODO: Review MsgMetaInfo implementation
    # TODO: Review MessageID implementation
    # TODO: Review Node.get_child_by_tag implementation
    # TODO: Review AttrGetter implementation
    # TODO: Review AttrGetter.optional_string implementation
    # TODO: Review AttrGetter.optional_jid_or_empty implementation
    # TODO: Review AttrGetter.get_bool implementation

    meta_info = MsgMetaInfo()

    meta_node = node.get_child_by_tag("meta")

    ag = meta_node.attr_getter()
    meta_info.target_id = MessageID(ag.optional_string("target_id"))
    meta_info.target_sender = ag.optional_jid_or_empty("target_sender_jid")

    deprecated_lid_session, ok = ag.get_bool("deprecated_lid_session", False)
    if ok:
        meta_info.deprecated_lid_session = deprecated_lid_session

    meta_info.thread_message_id = MessageID(ag.optional_string("thread_msg_id"))
    meta_info.thread_message_sender_jid = ag.optional_jid_or_empty("thread_msg_sender_jid")

    err = ag.error()
    return meta_info, err


async def parse_message_info(client: "Client", node: "Node") -> "MessageInfo":
    """
    Port of Go method parseMessageInfo from client.go.

    Parses complete message information from a binary node including message source,
    attributes, and child node content.

    Args:
        client: The WhatsApp client instance
        node: The binary node containing message information

    Returns:
        MessageInfo object
    Raises:
        Exception:
    """
    # TODO: Review MessageInfo implementation
    # TODO: Review parse_message_source implementation
    # TODO: Review AttrGetter implementation
    # TODO: Review parse_verified_name_content implementation
    # TODO: Review parse_msg_bot_info implementation
    # TODO: Review parse_msg_meta_info implementation
    # TODO: Review types.MessageID implementation
    # TODO: Review types.MessageServerID implementation
    # TODO: Review types.EditAttribute implementation

    ag = node.attr_getter()
    info = MessageInfo(id=MessageID(ag.string("id")))

    # Parse message source first
    message_source = await parse_message_source(client, node, True)
    info.message_source = message_source

    # Parse attributes
    info.server_id = MessageServerID(ag.optional_int("server_id"))
    info.timestamp = ag.unix_time("t")
    info.push_name = ag.optional_string("notify")
    info.category = ag.optional_string("category")
    info.type = ag.optional_string("type")
    info.edit = EditAttribute(ag.optional_string("edit"))

    if not ag.ok():
        err = ag.error()
        if err is not None:
            raise err

    # Parse child nodes
    for child in node.get_children():
        if child.tag == "multicast":
            info.multicast = True
        elif child.tag == "verified_name":
            try:
                verified_name = parse_verified_name_content(child)
                if verified_name is None:
                    logger.warning("Failed to parse verified_name node in %s", info.id)
                else:
                    info.verified_name = verified_name
            except Exception as e:
                logger.warning("Failed to parse verified_name node in %s: %v", info.id, e)
        elif child.tag == "bot":
            try:
                try:
                    bot_info = parse_msg_bot_info(child)
                    info.msg_bot_info = bot_info
                except Exception as e:
                    logger.exception(f"Failed to parse <bot> node in {info.id}: {e}")
            except Exception as e:
                logger.warning("Failed to parse <bot> node in %s: %v", info.id, e)
        elif child.tag == "meta":
            try:
                meta_info, err = parse_msg_meta_info(child)
                if err is not None:
                    logger.warning("Failed to parse <meta> node in %s: %v", info.id, err)
                else:
                    info.msg_meta_info = meta_info
            except Exception as e:
                logger.warning("Failed to parse <meta> node in %s: %v", info.id, e)
        elif child.tag == "franking":
            # TODO
            pass
        elif child.tag == "trace":
            # TODO
            pass
        else:
            child_ag = child.attr_getter()
            media_type, ok = child_ag.get_string("mediatype", False)
            if ok:
                info.media_type = media_type

    return info


async def handle_plaintext_message(client: "Client", info: "MessageInfo", node: "Node") -> None:
    """
    Port of Go method handlePlaintextMessage from message.go.

    Handles plaintext messages (typically from newsletters) by unmarshaling
    the protobuf content and dispatching the resulting message event.

    Args:
        client: The WhatsApp client instance
        info: Message information containing sender, timestamp, etc.
        node: The binary node containing the plaintext message

    Returns:
        None
    """
    # TODO: Review Node.get_optional_child_by_tag implementation
    # TODO: Review MessageInfo.source_string implementation
    # TODO: Review store_message_secret implementation
    # TODO: Review events.Message implementation
    # TODO: Review events.NewsletterMessageMeta implementation
    # TODO: Review dispatch_event implementation
    # TODO: Review waE2E_pb2.Message implementation

    from .datatypes import events

    # TODO edits have an additional <meta msg_edit_t="1696321271735" original_msg_t="1696321248"/> node
    plaintext, ok = node.get_optional_child_by_tag("plaintext")
    if not ok:
        # 3:
        return

    if not isinstance(plaintext.content, bytes):
        logger.warning("Plaintext message from %s doesn't have byte content", info.source_string())
        return

    plaintext_body = plaintext.content

    msg = WAWebProtobufsE2E_pb2.Message()
    try:
        msg.ParseFromString(plaintext_body)
    except Exception as err:
        logger.warning("Error unmarshaling plaintext message from %s: %v", info.source_string(), err)
        return

    await store_message_secret(client, info, msg)

    evt = events.Message(info=info, raw_message=msg)

    meta, ok = node.get_optional_child_by_tag("meta")
    if ok:
        evt.newsletter_meta = events.NewsletterMessageMeta(
            edit_ts=meta.attr_getter().unix_milli("msg_edit_t"),
            original_ts=meta.attr_getter().unix_time("original_msg_t"),
        )

    await client.dispatch_event(evt.unwrap_raw())


async def migrate_session_store(client: "Client", pn: "JID", lid: "JID") -> None:
    """Migrate session store from phone number to LID.

    Args:
        client: The WhatsApp client instance
        pn: Phone number JID
        lid: LID JID
    """
    try:
        await client.store.sessions.migrate_pn_to_lid(pn, lid)
    except Exception as e:
        logger.error(f"Failed to migrate signal store from {pn} to {lid}: {e}")


async def decrypt_messages(client: "Client", info: "MessageInfo", node: "Node") -> None:
    """
    Port of Go method decryptMessages from client.go.

    Decrypts encrypted messages from a binary node and handles different
    encryption types (pkmsg, msg, skmsg, msmsg).

    Args:
        client: The WhatsApp client instance
        info: Message information containing sender, timestamp, etc.
        node: The binary node containing encrypted messages

    Returns:
        None
    """
    # TODO: Review Node.get_optional_child_by_tag implementation
    # TODO: Review Node.get_children_by_tag implementation
    # TODO: Review events.UnavailableType implementation
    # TODO: Review events.UndecryptableMessage implementation
    # TODO: Review delayed_request_message_from_phone implementation
    # TODO: Review dispatch_event implementation
    # TODO: Review migrate_session_store implementation
    # TODO: Review decrypt_dm implementation
    # TODO: Review decrypt_group_msg implementation
    # TODO: Review decrypt_bot_message implementation
    # TODO: Review handle_decrypted_message implementation
    # TODO: Review handle_decrypted_armadillo implementation
    # TODO: Review send_retry_receipt implementation
    # TODO: Review send_message_receipt implementation
    # TODO: Review EventAlreadyProcessed exception
    # TODO: Review signalerror.ErrNoSenderKeyForUser exception
    from signal_protocol import error as signal_error

    from . import retry
    from .datatypes import events

    unavailable_node, ok = node.get_optional_child_by_tag("unavailable")
    if ok and len(node.get_children_by_tag("enc")) == 0:
        u_type = events.UnavailableType(unavailable_node.attr_getter().string("type"))
        logger.warning("Unavailable message %s from %s (type: %q)", info.id, info.source_string(), u_type)
        await retry.delayed_request_message_from_phone(client, info)
        await client.dispatch_event(
            events.UndecryptableMessage(info=info, is_unavailable=True, unavailable_type=u_type)
        )
        return

    children = node.get_children()
    logger.debug("Decrypting message from %s", info.source_string())
    handled = False
    contains_direct_msg = False
    sender_encryption_jid = info.sender

    # Handle LID/PN migration logic
    if info.sender.server == DEFAULT_USER_SERVER and not info.sender.is_bot():
        if info.sender_alt.server == HIDDEN_USER_SERVER:
            sender_encryption_jid = info.sender_alt
            await migrate_session_store(client, info.sender, info.sender_alt)
        else:
            try:
                lid = await client.store.lids.get_lid_for_pn(info.sender)
                if lid and not lid.is_empty():
                    await migrate_session_store(client, info.sender, lid)
                    sender_encryption_jid = lid
                    info.message_source.sender_alt = lid
                else:
                    logger.warning("No LID found for %s", info.sender)
            except Exception as err:
                logger.error("Failed to get LID for %s: %v", info.sender, err)

    for child in children:
        if child.tag != "enc":
            continue

        ag = child.attr_getter()
        enc_type, ok = ag.get_string("type", False)
        if not ok:
            continue

        ciphertext_hash: Optional[bytes]
        try:
            if enc_type == "pkmsg" or enc_type == "msg":
                decrypted, ciphertext_hash = await decrypt_dm(
                    client, child, sender_encryption_jid, enc_type == "pkmsg", info.timestamp
                )
                contains_direct_msg = True
            elif info.message_source.is_group and enc_type == "skmsg":
                decrypted, ciphertext_hash = await decrypt_group_msg(
                    client, child, sender_encryption_jid, info.chat, info.timestamp
                )
            elif enc_type == "msmsg" and info.sender.is_bot():
                target_sender_jid = info.msg_meta_info.target_sender
                message_secret_sender_jid = target_sender_jid

                if target_sender_jid.user == "":
                    if info.sender.server == BOT_SERVER:
                        target_sender_jid = client.store.get_lid()
                    else:
                        target_sender_jid = client.get_own_id()
                    message_secret_sender_jid = client.get_own_id()

                if info.msg_bot_info.edit_type == BotEditType.INNER or info.msg_bot_info.edit_type == BotEditType.LAST:
                    decrypt_message_id = info.msg_bot_info.edit_target_id
                    assert decrypt_message_id is not None
                else:
                    decrypt_message_id = info.id

                # Get message secret
                assert info.msg_meta_info.target_id is not None
                message_secret = await client.store.msg_secrets.get_message_secret(
                    info.chat, message_secret_sender_jid, info.msg_meta_info.target_id
                )

                if message_secret is None:
                    raise Exception(f"message secret for {info.msg_meta_info.target_id} not found")

                # Parse MessageSecretMessage protobuf
                ms_msg = WAWebProtobufsE2E_pb2.MessageSecretMessage()
                assert isinstance(child.content, bytes)
                ms_msg.ParseFromString(child.content)

                # Decrypt bot message
                decrypted = await decrypt_bot_message(
                    message_secret, ms_msg, decrypt_message_id, target_sender_jid, info
                )
                # Bot messages don't have ciphertext hash in the same way
                ciphertext_hash = None
            else:
                logger.warning("Unhandled encrypted message (type %s) from %s", enc_type, info.source_string())
                continue

        except EventAlreadyProcessed as e:
            logger.debug("Ignoring message %s from %s: %v", info.id, info.source_string(), e)
            return
        except Exception as e:
            logger.warning("Error decrypting message from %s: %v", info.source_string(), e)

            # Check for specific signal protocol errors
            # The signal_protocol library uses different error types
            is_no_sender_key_error = (
                isinstance(e, signal_error.SignalProtocolException) and "no sender key" in str(e).lower()
            )

            is_unavailable = enc_type == "skmsg" and not contains_direct_msg and is_no_sender_key_error

            if enc_type != "msmsg":
                await retry.send_retry_receipt(client, node, info, is_unavailable)

            await client.dispatch_event(
                events.UndecryptableMessage(
                    info=info,
                    is_unavailable=is_unavailable,
                    decrypt_fail_mode=events.DecryptFailMode(ag.optional_string("decrypt-fail")),
                )
            )
            return

        # Handle successful decryption
        retry_count = ag.optional_int("count")
        await retry.cancel_delayed_request_from_phone(client, info.id)

        version = ag.int("v")
        if version == 2:
            try:
                msg = WAWebProtobufsE2E_pb2.Message()
                msg.ParseFromString(decrypted)
                await handle_decrypted_message(client, info, msg, retry_count)
                handled = True
            except Exception as parse_err:
                logger.warning("Error unmarshaling decrypted message from %s: %v", info.source_string(), parse_err)
                continue
        elif version == 3:
            handled = await handle_decrypted_armadillo(client, info, decrypted, retry_count)
        else:
            logger.warning("Unknown version %d in decrypted message from %s", version, info.source_string())

        # Handle event buffer cleanup
        if ciphertext_hash is not None and client.enable_decrypted_event_buffer:
            try:
                await client.store.event_buffer.clear_buffered_event_plaintext(ciphertext_hash)
                logger.debug("Deleted event plaintext from buffer (ciphertext_hash: %s)", ciphertext_hash.hex())
            except Exception as err:
                logger.error(
                    "Failed to clear buffered event plaintext: %s (ciphertext_hash: %s)", err, ciphertext_hash.hex()
                )

            # Periodic cleanup of old buffered hashes
            current_time = datetime.now()
            if (
                client.last_decrypted_buffer_clear is None
                or (current_time - client.last_decrypted_buffer_clear).total_seconds() > 12 * 3600
            ):  # 12 hours
                client.last_decrypted_buffer_clear = current_time

                try:
                    await client.store.event_buffer.delete_old_buffered_hashes()
                except Exception as err:
                    logger.error("Failed to delete old buffered hashes: %s", err)

    if handled:
        await send_message_receipt(client, info)


async def clear_untrusted_identity(client: "Client", target: "JID") -> None:
    """
    Port of Go method clearUntrustedIdentity from client.go.

    Clears an untrusted identity by deleting both the identity and session for the target JID,
    then dispatches an IdentityChange event.

    Args:
        client:
        target: The target JID whose identity should be cleared

    Returns: None
    Raises:
        Exception:
    """
    # TODO: Review Store.Identities.DeleteIdentity implementation
    # TODO: Review Store.Sessions.DeleteSession implementation
    # TODO: Review dispatchEvent implementation
    # TODO: Review events.IdentityChange implementation

    await client.store.identities.delete_identity(str(target.signal_address()))
    await client.store.sessions.delete_session(str(target.signal_address()))
    await client.dispatch_event(events.IdentityChange(jid=target, timestamp=datetime.now(), implicit=True))


async def buffered_decrypt(
    client: "Client", ciphertext: bytes, server_timestamp: datetime, decrypt: Callable[[], Awaitable[bytes]]
) -> Tuple[bytes, bytes]:
    """
    Port of Go method bufferedDecrypt from client.go.

    Performs buffered decryption with caching to avoid re-decrypting the same message.
    If buffering is disabled, directly calls the decrypt function.

    Args:
        client:
        ciphertext: The encrypted message bytes
        server_timestamp: Timestamp from the server
        decrypt: Function that performs the actual decryption

    Returns:
        Tuple containing (plaintext, ciphertext_hash)
    Raises:

    """
    # TODO: Review Store.EventBuffer.GetBufferedEvent implementation
    # TODO: Review Store.EventBuffer.DoDecryptionTxn implementation
    # TODO: Review Store.EventBuffer.PutBufferedEvent implementation
    # TODO: Review store.BufferedEvent implementation
    # TODO: Review EventAlreadyProcessed exception

    if not client.enable_decrypted_event_buffer:
        plaintext = await decrypt()
        return plaintext, b""

    ciphertext_hash = hashlib.sha256(ciphertext).digest()
    buf = await client.store.event_buffer.get_buffered_event(ciphertext_hash)
    if buf is not None:
        if buf.plaintext is None:
            logger.debug(
                "Returning event already processed error (ciphertext_hash: %s, insertion_time: %s)",
                ciphertext_hash.hex(),
                buf.insert_time,
            )
            raise Exception(f"{EventAlreadyProcessed} at {buf.insert_time}")

        logger.debug(
            "Returning previously decrypted plaintext (ciphertext_hash: %s, insertion_time: %s)",
            ciphertext_hash.hex(),
            buf.insert_time,
        )
        return buf.plaintext, ciphertext_hash

    plaintext = b""

    async def txn_func() -> None:
        nonlocal plaintext
        plaintext = await decrypt()
        await client.store.event_buffer.put_buffered_event(ciphertext_hash, plaintext, server_timestamp)

    await client.store.event_buffer.do_decryption_txn(txn_func())
    return plaintext, ciphertext_hash


async def decrypt_dm(
    client: "Client", child: "Node", from_jid: "JID", is_pre_key: bool, server_ts: datetime
) -> Tuple[bytes, bytes]:
    """
    Port of Go method decryptDM from client.go.

    Decrypts a direct message using Signal protocol, handling both prekey and normal messages.
    Uses buffered decryption to avoid re-decrypting the same message.

    Args:
        client:
        child: The binary node containing the encrypted message
        from_jid: The sender's JID
        is_pre_key: Whether this is a prekey message
        server_ts: Server timestamp

    Returns:
        Tuple containing (plaintext, ciphertext_hash)
    Raises:
        ValueError: If message content is not bytes
        Exception: Various decryption/parsing errors
    """
    content = child.content
    if not isinstance(content, bytes):
        raise ValueError("message content is not a byte slice")

    # Create the remote address for the sender - equivalent to from.SignalAddress()
    remote_addr = signal_protocol.address.ProtocolAddress(from_jid.user, from_jid.device)

    if is_pre_key:
        # Parse prekey message - equivalent to protocol.NewPreKeySignalMessageFromBytes
        pre_key_msg = signal_protocol.protocol.PreKeySignalMessage.try_from(content)

        # Use buffered decryption for prekey messages
        async def decrypt_prekey_func() -> bytes:
            try:
                return signal_protocol.session_cipher.message_decrypt_prekey(
                    client.signal_store, remote_addr, pre_key_msg
                )
            except Exception as inner_err:
                # Handle untrusted identity error - equivalent to AutoTrustIdentity logic
                if client.auto_trust_identity and "untrusted identity" in str(inner_err).lower():
                    logger.warning(
                        f"Got untrusted identity error while trying to decrypt prekey message from {from_jid}, clearing stored identity and retrying"
                    )
                    await clear_untrusted_identity(client, from_jid)
                    return signal_protocol.session_cipher.message_decrypt_prekey(
                        client.signal_store, remote_addr, pre_key_msg
                    )
                else:
                    raise inner_err

        plaintext, ciphertext_hash = await buffered_decrypt(client, content, server_ts, decrypt_prekey_func)

    else:
        # Parse normal signal message - equivalent to protocol.NewSignalMessageFromBytes
        signal_msg = signal_protocol.protocol.SignalMessage.try_from(content)

        # Use buffered decryption for normal messages
        async def decrypt_normal_func() -> bytes:
            return signal_protocol.session_cipher.message_decrypt_signal(client.signal_store, remote_addr, signal_msg)

        plaintext, ciphertext_hash = await buffered_decrypt(client, content, server_ts, decrypt_normal_func)

    # Unpad the message - equivalent to unpadMessage(plaintext, child.AttrGetter().Int("v"))
    version = child.attr_getter().int("v")
    plaintext = unpad_message(plaintext, version)

    return plaintext, ciphertext_hash


async def decrypt_group_msg(
    client: "Client", child: "Node", from_jid: "JID", chat: "JID", server_ts: datetime
) -> Tuple[bytes, bytes]:
    """
    Port of Go method decryptGroupMsg from client.go.

    Decrypts a group message using Signal protocol sender key.
    Uses buffered decryption to avoid re-decrypting the same message.

    Args:
        client:
        child: The binary node containing the encrypted message
        from_jid: The sender's JID
        chat: The group chat JID
        server_ts: Server timestamp

    Returns:
        Tuple containing (plaintext, ciphertext_hash, error)
    Raises:
        ValueError: If message content is not bytes
        Exception: Various decryption/parsing errors
    """
    # TODO: Review waBinary.Node implementation
    # TODO: Review protocol.NewSenderKeyName implementation
    # TODO: Review groups.NewGroupSessionBuilder implementation
    # TODO: Review groups.NewGroupCipher implementation
    # TODO: Review protocol.NewSenderKeyMessageFromBytes implementation
    # TODO: Review pbSerializer implementation
    # TODO: Review unpad_message implementation
    # Check content is bytes
    content = child.content
    if not isinstance(content, bytes):
        raise ValueError("message content is not bytes")
    # Create sender key name (equivalent to protocol.NewSenderKeyName)
    sender_address = signal_protocol.address.ProtocolAddress(from_jid.user, from_jid.device)
    sender_key_name = signal_protocol.sender_keys.SenderKeyName(group_id=str(chat), sender=sender_address)

    async def decrypt_func() -> bytes:
        # Decrypt using group cipher - equivalent to cipher.Decrypt(decryptCtx, msg)
        return signal_protocol.group_cipher.group_decrypt(
            skm_bytes=content, protocol_store=client.signal_store, sender_key_id=sender_key_name
        )

    plaintext, ciphertext_hash = await buffered_decrypt(client, content, server_ts, decrypt_func)

    # Unpad the message
    # Go: plaintext, err = unpadMessage(plaintext, child.AttrGetter().Int("v"))
    version = child.attr_getter().int("v")
    plaintext = unpad_message(plaintext, version)

    return plaintext, ciphertext_hash


def is_valid_padding(plaintext: bytes) -> bool:
    """
    Port of Go function isValidPadding from padding.go.

    Validates PKCS#7 padding by checking if the last byte value
    matches the number of padding bytes at the end.

    Args:
        plaintext: The byte array to validate padding for

    Returns:
        True if padding is valid, False otherwise
    """
    if not plaintext:
        return False

    last_byte = plaintext[-1]
    expected_padding = bytes([last_byte] * last_byte)
    return plaintext.endswith(expected_padding)


def unpad_message(plaintext: bytes, version: int) -> bytes:
    """
    Port of Go function unpadMessage from padding.go.

    Removes PKCS#7 padding from plaintext based on version.
    Version 3 messages don't use padding, others do.

    Args:
        plaintext: The byte array to remove padding from
        version: Message version (3 = no padding, others = padded)

    Returns:
        Tuple containing (unpadded_bytes, error)
    Raises:
        Exception:
    """
    # TODO: Review checkPadding global variable implementation
    # TODO: Review is_valid_padding implementation

    if version == 3:
        return plaintext
    elif len(plaintext) == 0:
        raise Exception("plaintext is empty")
    elif CHECK_PADDING and not is_valid_padding(plaintext):
        raise Exception("plaintext doesn't have expected padding")
    else:
        padding_length = plaintext[len(plaintext) - 1]
        return plaintext[: len(plaintext) - padding_length]


def pad_message(plaintext: bytes) -> bytes:
    """
    Port of Go function padMessage from padding.go.

    Adds PKCS#7-style padding to plaintext using a random padding byte.
    The padding length is between 1-15 bytes, determined by the random byte value.

    Args:
        plaintext: The byte array to add padding to

    Returns:
        The padded byte array
    """
    pad = os.urandom(1)
    pad_byte = pad[0] & 0xF
    if pad_byte == 0:
        pad_byte = 0xF

    padding = bytes([pad_byte]) * pad_byte
    return plaintext + padding


async def handle_sender_key_distribution_message(
    client: "Client", chat: "JID", from_jid: "JID", axolotl_skdm: bytes
) -> None:
    """
    Port of Go method handleSenderKeyDistributionMessage from client.go.

    Processes a sender key distribution message for group chat encryption.
    Parses the message and updates the group session builder with the new key.

    Args:
        client:
        chat: The group chat JID
        from_jid: The sender's JID
        axolotl_skdm: The sender key distribution message bytes

    Returns:
        None
    """
    try:
        # Create sender key name (equivalent to protocol.NewSenderKeyName)
        sender_key_name = signal_protocol.sender_keys.SenderKeyName(
            group_id=str(chat),  # chat.String() in Go
            sender=signal_protocol.address.ProtocolAddress(
                from_jid.user, from_jid.device
            ),  # from.SignalAddress() in Go
        )

        # Parse sender key distribution message from bytes
        skd_msg = signal_protocol.protocol.SenderKeyDistributionMessage.try_from(axolotl_skdm)

        # Process the sender key distribution message
        # This is equivalent to: builder.Process(ctx, senderKeyName, sdkMsg)
        process_sender_key_distribution_message(
            protocol_store=client.signal_store,
            sender_key_name=sender_key_name,
            skdm=skd_msg,
        )

        logger.debug(f"Processed sender key distribution message from {from_jid} in {chat}")
    except Exception as err:
        logger.error(f"Failed to process sender key distribution message from {from_jid} for {chat}: {err}")


async def handle_history_sync_notification_loop(client: "Client") -> None:
    """
    Port of Go method handleHistorySyncNotificationLoop from client.go.

    Processes history sync notifications in a loop with error recovery.
    Automatically restarts if new notifications appear after the loop stops.

    Returns:
        None
    """
    try:
        # Process notifications from the queue
        while True:
            try:
                notif = await client.history_sync_notifications.get()
                await handle_history_sync_notification(client, notif)
                client.history_sync_notifications.task_done()
            except asyncio.CancelledError:
                break

    except Exception as err:
        logger.error("History sync handler panicked: %v\n%s", err, traceback.format_exc())

    finally:
        # Mark handler as stopped
        client.history_sync_handler_started = False

        # Check if new notifications appeared while stopping (simple compare-and-swap)
        if not client.history_sync_notifications.empty() and not client.history_sync_handler_started:
            client.history_sync_handler_started = True
            logger.warning("New history sync notifications appeared after loop stopped, restarting loop...")
            # Start new async task for the loop
            client.create_task(handle_history_sync_notification_loop(client))


async def handle_history_sync_notification(client: "Client", notif: HistorySyncNotification) -> None:
    """
    Port of Go method handleHistorySyncNotification from client.go.

    Downloads, decompresses, and processes a history sync notification.
    Handles push names and conversation data, then dispatches a HistorySync event.

    Args:
        client:
        notif: The history sync notification to process

    Returns:
        None
    """
    # TODO: Review Download implementation
    # TODO: Review handle_historical_push_names implementation
    # TODO: Review store_historical_message_secrets implementation
    # TODO: Review dispatch_event implementation
    # TODO: Review proto.unmarshal implementation
    from .datatypes import events

    history_sync: Optional[WAWebProtobufsHistorySync_pb2.HistorySync] = None

    try:
        # Download the history sync data
        data = await download(client, notif)
        if data is None:
            logger.warning("Failed to download history sync data for %s", notif)
            return
    except Exception as err:
        logger.error("Failed to download history sync data: %v", err)
        return

    try:
        # Create zlib reader and decompress
        reader = zlib.decompressobj()
        raw_data = reader.decompress(data)
        raw_data += reader.flush()
    except Exception as err:
        logger.error("Failed to decompress history sync data: %v", err)
        return

    try:
        # Unmarshal protobuf data
        history_sync = WAWebProtobufsHistorySync_pb2.HistorySync()
        history_sync.ParseFromString(raw_data)
    except Exception as err:
        logger.error("Failed to unmarshal history sync data: %v", err)
        return

    # Successfully processed - handle the data
    logger.debug("Received history sync (type %s, chunk %d)", history_sync.syncType, history_sync.chunkOrder)

    # Handle different sync types
    if history_sync.syncType == WAWebProtobufsHistorySync_pb2.HistorySync.PUSH_NAME:
        # Start async task for handling push names
        client.create_task(handle_historical_push_names(client, history_sync.pushnames))
    elif len(history_sync.conversations) > 0:
        # Start async task for storing message secrets
        client.create_task(store_historical_message_secrets(client, history_sync.conversations))

    # Dispatch the history sync event
    await client.dispatch_event(events.HistorySync(data=history_sync))


async def handle_app_state_sync_key_share(client: "Client", keys: WAWebProtobufsE2E_pb2.AppStateSyncKeyShare) -> None:
    """
    Port of Go method handleAppStateSyncKeyShare from client.go.

    Handles incoming app state sync key shares by storing the keys
    and triggering fetches for all app state patch types.

    Args:
        client:
        keys: The app state sync key share containing new keys

    Returns:
        None
    """
    # TODO: Review Store.AppStateKeys implementation
    # TODO: Review FetchAppState implementation
    # TODO: Review appstate.AllPatchNames implementation
    # TODO: Review store.AppStateSyncKey implementation

    only_resync_if_not_synced = True

    logger.debug("Got %d new app state keys", len(keys.keys))

    async with client.app_state_key_requests_lock:
        for key in keys.keys:
            try:
                # Marshal fingerprint using protobuf's built-in method
                marshaled_fingerprint = key.keyData.fingerprint.SerializeToString()
            except Exception as e:
                logger.error(
                    f"Failed to marshal fingerprint of app state sync key {key.keyID.keyID.hex().upper()}: {e}",
                )
                continue

            key_id_hex = key.keyID.keyID.hex()
            is_re_request = key_id_hex in client.app_state_key_requests

            if is_re_request:
                only_resync_if_not_synced = False

            try:
                await client.store.app_state_keys.put_app_state_sync_key(
                    key.keyID.keyID,
                    store.AppStateSyncKey(
                        data=key.keyData.keyData, fingerprint=marshaled_fingerprint, timestamp=key.keyData.timestamp
                    ),
                )
            except Exception as err:
                logger.error("Failed to store app state sync key %s: %v", key.keyID.keyID.hex().upper(), err)
                continue

            logger.debug(
                "Received app state sync key %s (ts: %d)", key.keyID.keyID.hex().upper(), key.keyData.timestamp
            )

    # Fetch app state for all patch names
    for name in ALL_PATCH_NAMES:
        try:
            from py.pymeow.appstate import fetch_app_state

            await fetch_app_state(client, name, False, only_resync_if_not_synced)
        except Exception as err:
            logger.error("Failed to do initial fetch of app state %s: %v", name, err)


async def handle_placeholder_resend_response(
    client: "Client", msg: WAWebProtobufsE2E_pb2.PeerDataOperationRequestResponseMessage
) -> None:
    """
    Port of Go method handlePlaceholderResendResponse from client.go.

    Handles responses to placeholder resend requests by parsing the web messages
    and dispatching events for successfully parsed messages.

    Args:
        client
        msg: The peer data operation request response message

    Returns:
        None
    """
    # TODO: Review ParseWebMessage implementation
    # TODO: Review dispatch_event implementation
    # TODO: Review types.EmptyJID implementation

    req_id = MessageID(msg.stanzaID)
    parts = msg.peerDataOperationResult

    logger.debug("Handling response to placeholder resend request %s with %d items", req_id, len(parts))

    for i, part in enumerate(parts):
        resp = part.placeholderMessageResendResponse
        if resp is None:
            logger.warning("Missing response in item #%d of response to %s", i + 1, req_id)
            continue

        # Create new WebMessageInfo and parse protobuf data
        web_msg = WAWebProtobufsWeb_pb2.WebMessageInfo()
        try:
            web_msg.ParseFromString(resp.webMessageInfoBytes)
        except Exception as err:
            logger.warning(
                "Failed to unmarshal protobuf web message in item #%d of response to %s: %v", i + 1, req_id, err
            )
            continue

        # Parse the web message
        try:
            msg_evt = client.parse_web_message(EMPTY_JID, web_msg)
        except Exception as err:
            logger.warning("Failed to parse web message info in item #%d of response to %s: %v", i + 1, req_id, err)
            continue

        # Set the unavailable request ID and dispatch the event
        msg_evt.unavailable_request_id = req_id
        await client.dispatch_event(msg_evt)


async def handle_protocol_message(client: "Client", info: "MessageInfo", msg: WAWebProtobufsE2E_pb2.Message) -> None:
    """
    Port of Go method handleProtocolMessage from client.go.

    Handles protocol messages by processing different types of protocol operations
    including history sync notifications, placeholder resend responses, and app state sync.

    Args:
        client: The WhatsApp client instance
        info: Message information
        msg: The protocol message to handle

    Returns:
        None
    """
    # TODO: Review types.MessageInfo implementation
    # TODO: Review handle_history_sync_notification implementation
    # TODO: Review send_protocol_message_receipt implementation
    # TODO: Review handle_placeholder_resend_response implementation
    # TODO: Review handle_app_state_sync_key_share implementation
    # TODO: Review types.ReceiptTypeHistorySync implementation
    # TODO: Review types.ReceiptTypePeerMsg implementation
    from .datatypes import ReceiptType

    proto_msg = msg.protocolMessage

    # Handle history sync notification
    if proto_msg.historySyncNotification is not None and info.is_from_me:
        # Send notification to channel (using asyncio queue)
        await client.history_sync_notifications.put(proto_msg.historySyncNotification)

        # Start handler loop if not already started (simple compare and swap equivalent)
        if not client.history_sync_handler_started:
            client.history_sync_handler_started = True
            client.create_task(handle_history_sync_notification_loop(client))

        # Send receipt asynchronously
        await send_protocol_message_receipt(client, info.id, ReceiptType.HISTORY_SYNC)

    # Handle placeholder message resend response
    peer_data_msg = proto_msg.peerDataOperationRequestResponseMessage
    if (
        peer_data_msg is not None
        and peer_data_msg.peerDataOperationRequestType
        == WAWebProtobufsE2E_pb2.PeerDataOperationRequestType.PLACEHOLDER_MESSAGE_RESEND
    ):
        await handle_placeholder_resend_response(client, peer_data_msg)

    # Handle app state sync key share
    if proto_msg.appStateSyncKeyShare is not None and info.is_from_me:
        # Note: Go's context.WithoutCancel creates a context that won't be cancelled
        # In Python, we'll pass the original context since cancellation is handled differently
        await handle_app_state_sync_key_share(client, proto_msg.appStateSyncKeyShare)

    # Handle peer category messages
    if info.category == "peer":
        await send_protocol_message_receipt(client, info.id, ReceiptType.PEER_MSG)


async def process_protocol_parts(client: "Client", info: "MessageInfo", msg: WAWebProtobufsE2E_pb2.Message) -> None:
    """
    Port of Go method processProtocolParts from client.go.

    Processes protocol-related parts of a message including storing message secrets,
    handling device-sent messages, sender key distribution, and protocol messages.

    Args:
        client:
        info: Message information
        msg: The message to process

    Returns:
        None
    """
    # TODO: Review store_message_secret implementation
    # TODO: Review handle_sender_key_distribution_message implementation
    # TODO: Review handle_protocol_message implementation
    # TODO: Review types.DEFAULT_USER_SERVER implementation
    # TODO: Review types.HIDDEN_USER_SERVER implementation

    await store_message_secret(client, info, msg)

    # Hopefully sender key distribution messages and protocol messages can't be inside ephemeral messages
    if msg.deviceSentMessage.message is not None:
        msg = msg.deviceSentMessage.message

    if msg.senderKeyDistributionMessage is not None:
        if not info.message_source.is_group:
            logger.warning("Got sender key distribution message in non-group chat from %s", info.sender)
        else:
            encryption_identity = info.sender
            if encryption_identity.server == DEFAULT_USER_SERVER and info.sender_alt.server == HIDDEN_USER_SERVER:
                encryption_identity = info.sender_alt

            await handle_sender_key_distribution_message(
                client,
                info.chat,
                encryption_identity,
                msg.senderKeyDistributionMessage.axolotlSenderKeyDistributionMessage,
            )

    # N.B. Edits are protocol messages, but they're also wrapped inside EditedMessage,
    # which is only unwrapped after process_protocol_parts, so this won't trigger for edits.
    if msg.protocolMessage is not None:
        await handle_protocol_message(client, info, msg)


async def store_message_secret(client: "Client", info: "MessageInfo", msg: WAWebProtobufsE2E_pb2.Message) -> None:
    """
    Port of Go method storeMessageSecret from client.go.

    Stores the message secret key if present in the message context info.

    Args:
        client:
        info: Message information containing chat, sender, and message ID
        msg: The message containing potential secret information

    Returns:
        None
    """
    # TODO: Review Store.MsgSecrets.put_message_secret implementation

    msg_secret = msg.messageContextInfo.messageSecret
    if len(msg_secret) > 0:
        try:
            await client.store.msg_secrets.put_message_secret(info.chat, info.sender, info.id, msg_secret)
            logger.debug("Stored message secret key for %s", info.id)
        except Exception as err:
            logger.error("Failed to store message secret key for %s: %v", info.id, err)


async def store_historical_message_secrets(
    client: "Client", conversations: Iterable[WAWebProtobufsHistorySync_pb2.Conversation]
) -> None:
    """
    Port of Go method storeHistoricalMessageSecrets from client.go.

    Stores message secrets and privacy tokens from historical conversations.

    Args:
        client:
        conversations: List of conversations from history sync

    Returns:
        None
    """
    # TODO: Review store.MessageSecretInsert implementation
    # TODO: Review store.PrivacyToken implementation
    # TODO: Review get_own_id implementation
    # TODO: Review types.parse_jid implementation
    # TODO: Review types.DEFAULT_USER_SERVER implementation
    from .datatypes import JID

    secrets: List[store.MessageSecretInsert] = []
    privacy_tokens: List[store.PrivacyToken] = []

    own_id = client.get_own_id().to_non_ad()
    if own_id.is_empty():
        return

    for conv in conversations:
        chat_jid = JID.parse_jid(conv.ID)
        if chat_jid.is_empty():
            continue

        # Handle privacy tokens for direct chats
        if chat_jid.server == DEFAULT_USER_SERVER and conv.tcToken is not None:
            ts = conv.tcTokenTimestamp
            if ts == 0:
                ts = conv.tcTokenTimestamp

            privacy_tokens.append(
                store.PrivacyToken(user=chat_jid, token=conv.tcToken, timestamp=datetime.fromtimestamp(ts))
            )

        # Process messages in conversation
        for msg in conv.messages:
            secret = msg.message.get_message_secret()
            if secret is not None:
                sender_jid = JID()
                msg_key = msg.message.get_key()

                # Determine sender JID based on message properties
                if msg_key.get_from_me():
                    sender_jid = own_id
                elif chat_jid.server == DEFAULT_USER_SERVER:
                    sender_jid = chat_jid
                elif msg_key.get_participant() != "":
                    sender_jid = JID.parse_jid(msg_key.get_participant())
                elif msg.message.get_participant() != "":
                    sender_jid = JID.parse_jid(msg.message.get_participant())

                if sender_jid.is_empty() or msg_key.get_id() == "":
                    continue

                secrets.append(
                    store.MessageSecretInsert(chat=chat_jid, sender=sender_jid, id=msg_key.get_id(), secret=secret)
                )

    # Store message secrets if any were found
    if len(secrets) > 0:
        logger.debug("Storing %d message secret keys in history sync", len(secrets))
        try:
            await client.store.msg_secrets.put_message_secrets(secrets)
            logger.info("Stored %d message secret keys from history sync", len(secrets))
        except Exception as err:
            logger.error("Failed to store message secret keys in history sync: %v", err)

    # Store privacy tokens if any were found
    if len(privacy_tokens) > 0:
        logger.debug("Storing %d privacy tokens in history sync", len(privacy_tokens))
        try:
            await client.store.privacy_tokens.put_privacy_tokens(privacy_tokens)
            logger.info("Stored %d privacy tokens from history sync", len(privacy_tokens))
        except Exception as err:
            logger.error("Failed to store privacy tokens in history sync: %v", err)


async def handle_decrypted_message(
    client: "Client", info: "MessageInfo", msg: WAWebProtobufsE2E_pb2.Message, retry_count: int
) -> None:
    """
    Port of Go method handleDecryptedMessage from client.go.

    Handles a decrypted message by processing protocol parts and dispatching the message event.

    Args:
        client:
        info: Message information
        msg: The decrypted message
        retry_count: Number of retry attempts for this message

    Returns:
        None
    """
    # TODO: Review process_protocol_parts implementation
    # TODO: Review events.Message implementation
    # TODO: Review dispatch_event implementation
    from .datatypes import events

    await process_protocol_parts(client, info, msg)

    evt = events.Message(
        info=info,  # Python: pass by reference (object), Go: pass by value with *info
        raw_message=msg,
        retry_count=retry_count,
    )

    await client.dispatch_event(evt.unwrap_raw())


async def send_protocol_message_receipt(client: "Client", id: MessageID, msg_type: "ReceiptType") -> None:
    """
    Port of Go method sendProtocolMessageReceipt from client.go.

    Sends a protocol message receipt acknowledgement.

    Args:
        id: Message ID to acknowledge
        msg_type: Type of receipt to send

    Returns:
        None
    """
    # TODO: Review Store.ID implementation
    # TODO: Review send_node implementation
    # TODO: Review waBinary.Node implementation
    # TODO: Review types.new_jid implementation
    # TODO: Review types.LEGACY_USER_SERVER implementation
    from .datatypes import JID

    client_id = client.store.id
    if len(id) == 0 or client_id is None:
        return

    try:
        await client.send_node(
            Node(
                tag="receipt",
                attrs=Attrs(
                    {
                        "id": str(id),
                        "type": str(msg_type),
                        "to": JID.new_jid(client_id.user, LEGACY_USER_SERVER),
                    }
                ),
                content=None,
            )
        )
    except Exception as err:
        logger.warning("Failed to send acknowledgement for protocol message %s: %v", id, err)
