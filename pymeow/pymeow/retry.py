"""
Retry logic for WhatsApp operations.

Port of whatsmeow/retry.go
"""
import asyncio
import logging
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional, Tuple

from signal_protocol.group_cipher import create_sender_key_distribution_message
from signal_protocol.sender_keys import SenderKeyName

from . import message, prekeys, send, sendfb
from .binary.node import Node
from .exceptions import ElementMissingError
from .generated.waE2E import WAWebProtobufsE2E_pb2 as WAE2E_pb2
from .generated.waE2E.WAWebProtobufsE2E_pb2 import Message
from .generated.waMsgApplication import WAMsgApplication_pb2
from .send import NodeExtraParams, get_media_type_from_message, get_type_from_message

# from .store import signal
from .types.events import Receipt
from .types.jid import DEFAULT_USER_SERVER, JID
from .types.message import MessageID, MessageInfo

if TYPE_CHECKING:
    from .client import Client

ECC_DJB_TYPE = 0x05  # Standard Curve25519 type identifier

# Number of sent messages to cache in memory for handling retry receipts.
RECENT_MESSAGES_SIZE = 256

# Timeout for recreating sessions (Go: recreateSessionTimeout = 1 * time.Hour)
RECREATE_SESSION_TIMEOUT = timedelta(hours=1)

# Delay before requesting a message from the phone (Go: RequestFromPhoneDelay = 5 * time.Second)
REQUEST_FROM_PHONE_DELAY = timedelta(seconds=5)

logger = logging.getLogger(__name__)


@dataclass
class RecentMessageKey:
    """Key for identifying a recent message in the cache."""
    to: JID
    id: MessageID


class RecentMessage:
    """Recent message data for retry handling."""

    def __init__(self, wa: Optional[WAE2E_pb2.Message] = None, fb: Optional[WAMsgApplication_pb2.MessageApplication] = None):
        self.wa = wa
        self.fb = fb

    def is_empty(self) -> bool:
        """Check if the message is empty."""
        return self.wa is None and self.fb is None


@dataclass
class IncomingRetryKey:
    """Key for tracking incoming retry requests."""
    jid: JID
    message_id: MessageID


async def add_recent_message(
    client: "Client",
    to: JID,
    message_id: MessageID,
    wa: Optional[WAE2E_pb2.Message],
    fb: Optional[WAMsgApplication_pb2.MessageApplication]
) -> None:
    """
    Port of Go method addRecentMessage from retry.go.

    Add a message to the recent messages cache using a circular buffer approach.
    Thread-safe operation that maintains a fixed-size cache of recent messages.

    Args:
        client: The WhatsApp client instance
        to: The recipient JID
        message_id: The message ID
        wa: The WhatsApp E2E message
        fb: The Facebook message application
    """
    # TODO: Review RecentMessageKey implementation
    # TODO: Review RecentMessage implementation

    async with client.recent_messages_lock:
        key = RecentMessageKey(to, message_id)

        # If the slot is already occupied, remove the old entry from the map
        if client.recent_messages_list[client.recent_messages_ptr].id != "":
            del client.recent_messages_map[client.recent_messages_list[client.recent_messages_ptr]]

        # Add the new message to the map and list
        client.recent_messages_map[key] = RecentMessage(wa=wa, fb=fb)
        client.recent_messages_list[client.recent_messages_ptr] = key

        # Move the pointer (circular buffer)
        client.recent_messages_ptr += 1
        if client.recent_messages_ptr >= len(client.recent_messages_list):
            client.recent_messages_ptr = 0

async def get_recent_message(client: "Client", to: JID, message_id: MessageID) -> RecentMessage:
    """
    Port of Go method getRecentMessage from retry.go.

    Retrieves a message from the recent messages cache using a read lock for thread safety.
    Returns the message if found, or a zero-value RecentMessage if not found.

    Args:
        client: The WhatsApp client instance
        to: The recipient JID
        message_id: The message ID

    Returns:
        The recent message, or a zero-value RecentMessage if not found
    """
    # TODO: Review RecentMessageKey implementation
    # TODO: Review RecentMessage implementation

    async with client.recent_messages_lock:
        key = RecentMessageKey(to, message_id)
        msg = client.recent_messages_map.get(key, RecentMessage())
    return msg


async def get_message_for_retry(
    client: "Client",
    receipt: Receipt,
    message_id: MessageID
) -> RecentMessage:
    """
    Port of Go method getMessageForRetry from retry.go.

    Retrieves a message for retry processing, first checking local cache then
    falling back to GetMessageForRetry method. Returns the message and any error.

    Args:
        client: The WhatsApp client instance
        receipt: The receipt event containing chat, sender information
        message_id: The message ID to retrieve

    Returns:
        RecentMessage
    Raises:
        Exception
    """
    # TODO: Review Receipt implementation
    # TODO: Review RecentMessage implementation
    # TODO: Review Client.GetMessageForRetry implementation

    msg = await get_recent_message(client, receipt.message_source.chat, message_id)

    if msg.is_empty():
        wa_msg = await get_message_for_retry(client, receipt.message_source.sender, receipt.message_source.chat, message_id)
        if wa_msg is None:
            raise Exception(f"couldn't find message {message_id}")
        else:
            logger.debug(
                "Found message in GetMessageForRetry to accept retry receipt for %s/%s from %s",
                receipt.message_source.chat, message_id, receipt.message_source.sender
            )
        msg = RecentMessage(wa=wa_msg)
    else:
        logger.debug(
            "Found message in local cache to accept retry receipt for %s/%s from %s",
            receipt.message_source.chat, message_id, receipt.message_source.sender
        )

    return msg


async def should_recreate_session(
    client: "Client",
    retry_count: int,
    jid: JID
) -> Tuple[str, bool]:
    """
    Port of Go method shouldRecreateSession from retry.go.

    Determines if a Signal session should be recreated based on session existence,
    retry count, and time since last recreation. Thread-safe operation.

    Args:
        client: The WhatsApp client instance
        retry_count: The current retry count
        jid: The JID to check for session recreation

    Returns:
        Tuple containing (reason string, recreate boolean)
    """
    # TODO: Review Store.ContainsSession implementation
    # TODO: Review JID.signal_address implementation
    # TODO: Review recreate_session_timeout constant

    async with client.session_recreate_history_lock:
        try:
            contains = client.signal_store.contains_session(jid.signal_address())
        except Exception as e:
            logger.exception(e)
            return "", False

        if not contains:
            client.session_recreate_history[jid] = datetime.now()
            return "we don't have a Signal session with them", True
        elif retry_count < 2:
            return "", False

        prev_time = client.session_recreate_history.get(jid)
        if prev_time is None or prev_time + RECREATE_SESSION_TIMEOUT < datetime.now():
            client.session_recreate_history[jid] = datetime.now()
            return "retry count > 1 and over an hour since last recreation", True

        return "", False

async def handle_retry_receipt(
    client: "Client",
    receipt: "Receipt",
    node: "Node"
) -> None:
    """
    Port of Go method handleRetryReceipt from retry.go.

    Handles an incoming retry receipt for an outgoing message. Processes retry logic,
    encryption, and message resending with proper error handling and logging.

    Args:
        client: The WhatsApp client instance
        receipt: The receipt event containing sender/chat information
        node: The binary node containing the retry information

    Raises:
        ElementMissingError
    """
    # TODO: Review ElementMissingError implementation
    # TODO: Review AttrGetter implementation
    # TODO: Review Node.get_optional_child_by_tag implementation
    # TODO: Review IncomingRetryKey implementation
    # TODO: Review prekey.Bundle implementation
    # TODO: Review groups.GroupSessionBuilder implementation
    # TODO: Review protocol.SenderKeyName implementation

    retry_child, ok = node.get_optional_child_by_tag("retry")
    if not ok:
        raise ElementMissingError(tag="retry", in_location="retry receipt")

    ag = retry_child.attr_getter()
    message_id = MessageID(ag.string("id"))
    timestamp = ag.unix_time("t")
    retry_count = ag.int("count")
    if not ag.ok():
        raise ag.error()

    msg = await get_message_for_retry(client, receipt, message_id)

    fb_consumer_msg = None
    # if msg.fb is not None:
    #     sub_proto = msg.fb.get_payload().get_sub_protocol().get_sub_protocol()
    #     fb_consumer_msg = sub_proto.decode()

    retry_key = IncomingRetryKey(receipt.message_source.sender, message_id)
    async with client.incoming_retry_request_counter_lock:
        client.incoming_retry_request_counter[retry_key] = client.incoming_retry_request_counter.get(retry_key, 0) + 1
        internal_counter = client.incoming_retry_request_counter[retry_key]

    if internal_counter >= 10:
        logger.warning("Dropping retry request from %s for %s: internal retry counter is %d", message_id,
                         receipt.message_source.sender, internal_counter)
        return None

    if receipt.message_source.is_group:
        try:
            sender_key_name = SenderKeyName(
                group_id=str(receipt.message_source.chat),  # Group JID as string
                sender=client.get_own_lid().signal_address()  # Your own ProtocolAddress
            )
            signal_skd_message = create_sender_key_distribution_message(
                sender_key_name=sender_key_name,
                protocol_store=client.signal_store
            )

            if msg.wa is not None:
                msg.wa.sender_key_distribution_message = WAE2E_pb2.SenderKeyDistributionMessage(
                    groupID=str(receipt.message_source.chat),
                    axolotlSenderKeyDistributionMessage=signal_skd_message.serialize()
                )
            # else:
            #     fb_skdm = WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage(
            #         groupID=str(receipt.message_source.chat),
            #         axolotlSenderKeyDistributionMessage=signal_skd_message.serialize()
            #     )
        except Exception as e:
            logger.warning(
                "Failed to create sender key distribution message to include in retry of %s in %s to %s: %v",
                message_id, receipt.message_source.chat, receipt.message_source.sender, e)
    elif receipt.message_source.is_from_me:
        if msg.wa is not None:
            msg.wa = WAE2E_pb2.Message(
                deviceSentMessage=WAE2E_pb2.DeviceSentMessage(
                    destinationJID=str(receipt.message_source.chat),
                    message=msg.wa
                )
            )
        # else:
        #     fb_dsm = WAMsgTransport_pb2.MessageTransport.Protocol.Integral.DeviceSentMessage(
        #         destinationJID=str(receipt.message_source.chat)
        #     )

    # Pre-retry callback for fb - TODO comment matches Go
    if client.pre_retry_callback is not None:
        if not client.pre_retry_callback(receipt, message_id, retry_count, msg.wa):
            logger.debug("Cancelled retry receipt in PreRetryCallback")
            return None

    franking_tag = None
    if msg.wa is not None:
        plaintext = msg.wa.SerializeToString()  # proto.Marshal equivalent
    # else:
    #     plaintext = msg.fb.SerializeToString()  # proto.Marshal equivalent
    #
    #     franking_hash = hmac.new(msg.fb.get_metadata().get_franking_key(), plaintext, hashlib.sha256)
    #     franking_tag = franking_hash.digest()

    _, has_keys = node.get_optional_child_by_tag("keys")
    bundle = None
    if has_keys:
        bundle = await prekeys.node_to_pre_key_bundle(receipt.message_source.sender.device, node)
    else:
        reason, recreate = await should_recreate_session(client, retry_count, receipt.message_source.sender)
        if recreate:
            logger.debug("Fetching prekeys for %s for handling retry receipt with no prekey bundle because %s",
                              receipt.message_source.sender, reason)
            keys = await prekeys.fetch_pre_keys(client, [receipt.message_source.sender])  # TODO: Review fetch_pre_keys implementation
            pre_key_resp = keys[receipt.message_source.sender]
            bundle, err = pre_key_resp.bundle, pre_key_resp.error
            if err is not None:
                raise Exception("failed to fetch prekeys") from err
            elif bundle is None:
                if keys:
                    len_keys = len(keys)
                else:
                    len_keys = None
                raise Exception(f"didn't get prekey bundle for {receipt.message_source.sender} (response size: {len_keys})")

    enc_attrs = {}
    msg_attrs = sendfb.MessageAttrs()  # TODO: Review MessageAttrs implementation
    if msg.wa is not None:
        msg_attrs.media_type = get_media_type_from_message(msg.wa)
        msg_attrs.type = get_type_from_message(msg.wa)
    elif fb_consumer_msg is not None:
        msg_attrs = sendfb.get_attrs_from_fb_message(fb_consumer_msg)
    else:
        msg_attrs.type = "text"

    if msg_attrs.media_type != "":
        enc_attrs["mediatype"] = msg_attrs.media_type

    include_device_identity = False
    if msg.wa is not None:
        encryption_identity = receipt.message_source.sender
        if receipt.message_source.sender.server == DEFAULT_USER_SERVER:  # TODO: Review types.DEFAULT_USER_SERVER
            try:
                lid_for_pn = await client.store.lids.get_lid_for_pn(receipt.message_source.sender)
                if lid_for_pn and not lid_for_pn.is_empty():
                    await message.migrate_session_store(client, receipt.message_source.sender, lid_for_pn)
                    encryption_identity = lid_for_pn
            except Exception as e:
                logger.warning("Failed to get LID for %s: %v", receipt.message_source.sender, e)

        encrypted, include_device_identity = await send.encrypt_message_for_device(
            client, plaintext, encryption_identity, bundle, enc_attrs)
    else:
        raise Exception("FB retry not yet implemented")
    #     payload = WAMsgTransport_pb2.MessageTransport.Payload(
    #         applicationPayload=WACommon_pb2.SubProtocol(
    #             payload=plaintext,
    #             version=sendfb.FB_MESSAGE_APPLICATION_VERSION  # TODO: Review FB_MESSAGE_APPLICATION_VERSION
    #         ),
    #         futureProof=WACommon_pb2.FutureProofBehavior.PLACEHOLDER
    #     )
        # try:
        #     encrypted, err = sendfb.encrypt_message_for_device_v3(client, payload, fb_skdm, fb_dsm, receipt.sender, bundle,
        #                                                           enc_attrs)
        # except Exception as e:
        #     return Exception(f"failed to encrypt message for retry: {e}")

    encrypted.attrs["count"] = retry_count

    attrs = {
        "to": node.attrs["from"],
        "type": msg_attrs.type,
        "id": message_id,
        "t": int(timestamp.timestamp()),
    }

    if not receipt.message_source.is_group:
        attrs["device_fanout"] = False

    for attr_name in ["participant", "recipient", "edit"]:
        if attr_name in node.attrs:
            attrs[attr_name] = node.attrs[attr_name]

    if msg.wa is not None:
        content = send.get_message_content(
            client, encrypted, msg.wa, attrs, include_device_identity, NodeExtraParams()  # TODO: Review NodeExtraParams
        )
    else:
        content = [
            encrypted,
            Node(tag="franking", content=[Node(tag="franking_tag", content=franking_tag)])
        ]

    await client.send_node(Node(
        tag="message",
        attrs=attrs,
        content=content
    ))
    logger.debug("Sent retry #%d for %s/%s to %s", retry_count, receipt.message_source.chat,
                 message_id, receipt.message_source.sender)
    return None


async def cancel_delayed_request_from_phone(client: "Client", msg_id: MessageID) -> None:
    """
    Port of Go method cancelDelayedRequestFromPhone from retry.go.

    Cancels a delayed request for a message from the phone if automatic rerequesting
    is enabled and no messenger config is set. Thread-safe operation using read lock.

    Args:
        client: The WhatsApp client instance
        msg_id: The message ID to cancel the delayed request for
    """
    # TODO: Review MessageID implementation

    if not client.automatic_message_rerequest_from_phone or client.messenger_config is not None:
        return

    async with client.pending_phone_rerequests_lock:
        cancel_pending_request = client.pending_phone_rerequests.get(msg_id)
        if cancel_pending_request is not None:
            cancel_pending_request()

async def delayed_request_message_from_phone(client: "Client", info: "MessageInfo") -> None:
    """
    Port of Go method delayedRequestMessageFromPhone from retry.go.

    Requests a message from the phone after a delay, with cancellation support.
    Thread-safe operation that prevents duplicate requests and handles cleanup.

    Args:
        client: The WhatsApp client instance
        info: The message info containing ID, chat, and sender details
    """
    # TODO: Review MessageInfo implementation
    # TODO: Review SendRequestExtra implementation
    # TODO: Review REQUEST_FROM_PHONE_DELAY constant

    if not client.automatic_message_rerequest_from_phone or client.messenger_config is not None:
        return

    await client.pending_phone_rerequests_lock.acquire()
    try:
        if info.id in client.pending_phone_rerequests:
            return

        # Create cancellation mechanism
        cancel_event = asyncio.Event()
        client.pending_phone_rerequests[info.id] = cancel_event.set
    finally:
        client.pending_phone_rerequests_lock.release()

    async def cleanup() -> None:
        await client.pending_phone_rerequests_lock.acquire()
        try:
            if info.id in client.pending_phone_rerequests:
                del client.pending_phone_rerequests[info.id]
        finally:
            client.pending_phone_rerequests_lock.release()

    try:
        # Wait for delay or cancellation (equivalent to Go's select statement)
        try:
            # This mimics Go's select case <-time.After vs <-ctx.Done()
            import time
            start_time = time.time()
            while time.time() - start_time < REQUEST_FROM_PHONE_DELAY.total_seconds():
                if cancel_event.is_set():
                    logger.debug("Cancelled delayed request for message %s from phone", info.id)
                    return
                await asyncio.sleep(0.1)  # Small sleep to prevent busy waiting
        except Exception as e:
            logger.exception(e)
            return

        # Send the message request
        try:
            _ = await send.send_message(
                client,
                client.get_own_id().to_non_ad(),
                send.build_unavailable_message_request(client, info.chat, info.sender, info.id),
                send.SendRequestExtra(peer=True)
            )
            logger.debug("Requested message %s from phone", info.id)
        except Exception as e:
            logger.warning(f"Failed to send request for unavailable message {info.id} to phone: {e}")
    finally:
        await cleanup()


async def clear_delayed_message_requests(client: "Client") -> None:
    """
    Port of Go method clearDelayedMessageRequests from retry.go.

    Clears all pending delayed message requests by cancelling them.
    Thread-safe operation using write lock protection.

    Args:
        client: The WhatsApp client instance
    """
    await client.pending_phone_rerequests_lock.acquire()
    try:
        for cancel in client.pending_phone_rerequests.values():
            cancel()
    finally:
        client.pending_phone_rerequests_lock.release()


async def send_retry_receipt(
    client: "Client",
    node: "Node",
    info: "MessageInfo",
    force_include_identity: bool
) -> None:
    """
    Port of Go method sendRetryReceipt from retry.go.

    Sends a retry receipt for an incoming message. Tracks retry counts,
    includes identity information when needed, and handles goroutine spawning.

    Args:
        client: The WhatsApp client instance
        node: The binary node containing the message
        info: The message info containing message details
        force_include_identity: Whether to force including identity information
    """
    id_str = node.attrs.get("id", "")
    children = node.get_children()
    retry_count_in_msg = 0
    if len(children) == 1 and children[0].tag == "enc":
        retry_count_in_msg = children[0].attr_getter().optional_int("count")

    async with client.message_retries_lock:  # todo: check if we really need a lock
        client.message_retries[id_str] = client.message_retries.get(id_str, 0) + 1
        retry_count = client.message_retries[id_str]
        # In case the message is a retry response, and we restarted in between, find the count from the message
        if retry_count == 1 and retry_count_in_msg > 0:
            retry_count = retry_count_in_msg + 1
            client.message_retries[id_str] = retry_count

    if retry_count > 5:
        logger.warning(f"Not sending any more retry receipts for {id_str}")
        return

    if retry_count == 1:
        # Go uses goroutine: go cli.delayedRequestMessageFromPhone(info)
        client.create_task(delayed_request_message_from_phone(client, info))

    # Prepare registration ID bytes (4 bytes, big endian)
    registration_id_bytes = struct.pack(">I", client.store.registration_id)

    attrs = {
        "id": id_str,
        "type": "retry",
        "to": node.attrs["from"]
    }

    if "recipient" in node.attrs:
        attrs["recipient"] = node.attrs["recipient"]
    if "participant" in node.attrs:
        attrs["participant"] = node.attrs["participant"]

    payload = Node(
        tag="receipt",
        attrs=attrs,
        content=[
            Node(tag="retry", attrs={
                "count": retry_count,
                "id": id_str,
                "t": node.attrs["t"],
                "v": 1
            }),
            Node(tag="registration", content=registration_id_bytes)
        ]
    )

    if retry_count > 1 or force_include_identity:
        try:
            key = await client.store.pre_keys.gen_one_pre_key()
            try:
                device_identity = client.store.account.SerializeToString()
            except Exception as e:
                logger.error("Failed to marshal account info: %v", e)
                return

            payload.content = payload.get_children() + [Node(
                tag="keys",
                content=[
                    Node(tag="type", content=bytes([ECC_DJB_TYPE])),
                    Node(tag="identity", content=client.store.identity_key.pub[:]),
                    prekeys.pre_key_to_node(key),  # TODO: Review pre_key_to_node implementation
                    prekeys.pre_key_to_node(client.store.signed_pre_key),
                    Node(tag="device-identity", content=device_identity)
                ]
            )]
        except Exception as e:
            logger.error("Failed to get prekey for retry receipt: %v", e)

    try:
        await client.send_node(payload)
    except Exception as e:
        logger.exception(f"Failed to send retry receipt for {id_str}: {e}")
