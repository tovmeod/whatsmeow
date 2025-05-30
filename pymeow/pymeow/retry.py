"""
Retry logic for WhatsApp operations.

Port of whatsmeow/retry.go
"""
import asyncio
import hmac
import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, TypeVar, Callable, Awaitable, Any, Tuple, Set, Union

from .binary.node import Node
from .generated.waCommon import WACommon_pb2
from .generated.waConsumerApplication import WAConsumerApplication_pb2
from .generated.waE2E import WAE2E_pb2
from .generated.waMsgApplication import WAMsgApplication_pb2
from .generated.waMsgTransport import WAMsgTransport_pb2
from .types.jid import JID
from .types.message import MessageID, MessageInfo

T = TypeVar('T')

# Number of sent messages to cache in memory for handling retry receipts.
RECENT_MESSAGES_SIZE = 256

# Timeout for recreating sessions
RECREATE_SESSION_TIMEOUT = timedelta(hours=1)

# Delay before requesting a message from the phone
REQUEST_FROM_PHONE_DELAY = timedelta(seconds=5)


@dataclass
class RecentMessageKey:
    """Key for identifying a recent message in the cache."""
    to: JID
    id: MessageID


@dataclass
class RecentMessage:
    """Recent message data for retry handling."""
    wa: Optional[WAE2E_pb2.Message] = None
    fb: Optional[WAMsgApplication_pb2.MessageApplication] = None

    def is_empty(self) -> bool:
        """Check if the message is empty."""
        return self.wa is None and self.fb is None


@dataclass
class IncomingRetryKey:
    """Key for tracking incoming retry requests."""
    jid: JID
    message_id: MessageID


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    def __init__(
        self,
        max_retries: int = 5,
        initial_delay: timedelta = timedelta(seconds=1),
        max_delay: timedelta = timedelta(minutes=5),
        multiplier: float = 2.0
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.multiplier = multiplier


async def with_retry(
    operation: Callable[[], Awaitable[T]],
    config: RetryConfig = RetryConfig(),
) -> T:
    """
    Execute an operation with exponential backoff retry.

    Args:
        operation: The async operation to execute
        config: Configuration for retry behavior

    Returns:
        The result of the operation

    Raises:
        Exception: The last error encountered if all retries fail
    """
    delay = config.initial_delay
    last_error = None

    for attempt in range(config.max_retries):
        try:
            return await operation()
        except Exception as e:
            last_error = e
            if attempt == config.max_retries - 1:
                raise

            await asyncio.sleep(delay.total_seconds())
            delay = min(
                delay * config.multiplier,
                config.max_delay
            )

    raise last_error  # Should never reach here due to raise in loop


class RetryHandler:
    """
    Handles message retry logic for WhatsApp.

    This class manages the retry mechanism for messages that fail to deliver,
    including handling retry receipts and retransmitting messages.
    """

    def __init__(self, client):
        """
        Initialize the retry handler.

        Args:
            client: The WhatsApp client instance
        """
        self.client = client
        self.logger = logging.getLogger("pymeow.retry")

        # Cache of recent messages for handling retry receipts
        self.recent_messages_map: Dict[RecentMessageKey, RecentMessage] = {}
        self.recent_messages_list: List[RecentMessageKey] = [RecentMessageKey(JID(""), "") for _ in range(RECENT_MESSAGES_SIZE)]
        self.recent_messages_ptr = 0

        # Counter for incoming retry requests
        self.incoming_retry_request_counter: Dict[IncomingRetryKey, int] = {}

        # Counter for message retries
        self.message_retries: Dict[MessageID, int] = {}

        # History of session recreations
        self.session_recreate_history: Dict[JID, datetime] = {}

        # Pending requests for messages from phone
        self.pending_phone_rerequests: Dict[MessageID, Callable[[], None]] = {}

        # Flag for automatic message rerequest from phone
        self.automatic_message_rerequest_from_phone = True

    def add_recent_message(self, to: JID, id: MessageID, wa: Optional[WAE2E_pb2.Message], fb: Optional[WAMsgApplication_pb2.MessageApplication]):
        """
        Add a message to the recent messages cache.

        Args:
            to: The recipient JID
            id: The message ID
            wa: The WhatsApp E2E message
            fb: The Facebook message application
        """
        key = RecentMessageKey(to, id)

        # If the slot is already occupied, remove the old entry
        if self.recent_messages_list[self.recent_messages_ptr].id != "":
            old_key = self.recent_messages_list[self.recent_messages_ptr]
            if old_key in self.recent_messages_map:
                del self.recent_messages_map[old_key]

        # Add the new message
        self.recent_messages_map[key] = RecentMessage(wa=wa, fb=fb)
        self.recent_messages_list[self.recent_messages_ptr] = key

        # Move the pointer
        self.recent_messages_ptr += 1
        if self.recent_messages_ptr >= len(self.recent_messages_list):
            self.recent_messages_ptr = 0

    def get_recent_message(self, to: JID, id: MessageID) -> RecentMessage:
        """
        Get a message from the recent messages cache.

        Args:
            to: The recipient JID
            id: The message ID

        Returns:
            The recent message, or an empty message if not found
        """
        key = RecentMessageKey(to, id)
        return self.recent_messages_map.get(key, RecentMessage())

    async def get_message_for_retry(self, receipt, message_id: MessageID) -> Tuple[RecentMessage, Optional[Exception]]:
        """
        Get a message for retry.

        Args:
            receipt: The receipt event
            message_id: The message ID

        Returns:
            A tuple of (message, error)
        """
        msg = self.get_recent_message(receipt.chat, message_id)

        if msg.is_empty():
            # Try to get the message from the client's message store
            wa_msg = self.client.get_message_for_retry(receipt.sender, receipt.chat, message_id)

            if wa_msg is None:
                return RecentMessage(), Exception(f"couldn't find message {message_id}")
            else:
                self.logger.debug(
                    f"Found message in GetMessageForRetry to accept retry receipt for {receipt.chat}/{message_id} from {receipt.sender}"
                )

            msg = RecentMessage(wa=wa_msg)
        else:
            self.logger.debug(
                f"Found message in local cache to accept retry receipt for {receipt.chat}/{message_id} from {receipt.sender}"
            )

        return msg, None

    async def should_recreate_session(self, retry_count: int, jid: JID) -> Tuple[str, bool]:
        """
        Determine if a session should be recreated.

        Args:
            retry_count: The current retry count
            jid: The JID to check

        Returns:
            A tuple of (reason, recreate)
        """
        # Check if we have a session with the JID
        try:
            contains_session = await self.client.store.contains_session(jid.signal_address())
        except Exception:
            return "", False

        if not contains_session:
            self.session_recreate_history[jid] = datetime.now()
            return "we don't have a Signal session with them", True
        elif retry_count < 2:
            return "", False

        # Check if we've recreated the session recently
        prev_time = self.session_recreate_history.get(jid)
        if prev_time is None or prev_time + RECREATE_SESSION_TIMEOUT < datetime.now():
            self.session_recreate_history[jid] = datetime.now()
            return "retry count > 1 and over an hour since last recreation", True

        return "", False

    async def handle_retry_receipt(self, receipt, node: Node) -> Optional[Exception]:
        """
        Handle an incoming retry receipt for an outgoing message.

        This method needs to:
        1. Parse retry information from the node
        2. Get the original message for retry
        3. Handle encryption/session recreation
        4. Rebuild and resend the message
        5. Include proper device identity and sender key distribution

        Args:
            receipt: The receipt event
            node: The binary node containing the retry information

        Returns:
            An exception if an error occurred, None otherwise
        """
        from .exceptions import ElementMissingError
        from .prekeys import node_to_pre_key_bundle

        # Get retry child node
        retry_child = node.get_child("retry")
        if not retry_child:
            return ElementMissingError(tag="retry", in_="retry receipt")

        # Parse retry information
        ag = retry_child.attr_getter()
        message_id = ag.string("id")
        timestamp = ag.unix_time("t")
        retry_count = ag.int("count")
        if not ag.ok():
            return ag.error()

        # Get the original message for retry
        try:
            msg, err = await self.get_message_for_retry(receipt, message_id)
            if err:
                return err
        except Exception as e:
            self.logger.error(f"Error getting message for retry: {e}")
            return e

        # Handle FB consumer message if present
        fb_consumer_msg = None
        if msg.fb is not None:
            try:
                sub_proto = msg.fb.payload.sub_protocol.sub_protocol
                if hasattr(sub_proto, "consumer_message"):
                    fb_consumer_msg = sub_proto.consumer_message
            except Exception as e:
                return Exception(f"Failed to decode consumer message for retry: {e}")

        # Track retry requests
        retry_key = IncomingRetryKey(receipt.sender, message_id)
        self.incoming_retry_request_counter[retry_key] = self.incoming_retry_request_counter.get(retry_key, 0) + 1
        internal_counter = self.incoming_retry_request_counter[retry_key]

        if internal_counter >= 10:
            self.logger.warning(f"Dropping retry request from {message_id} for {receipt.sender}: internal retry counter is {internal_counter}")
            return None

        # Handle sender key distribution message for groups
        fb_skdm = None
        fb_dsm = None
        if receipt.is_group:
            try:
                # Create sender key distribution message
                builder = self.client.store.create_group_session_builder()
                sender_key_name = receipt.chat.string()
                signal_skd_message = await builder.create(sender_key_name, self.client.get_own_lid().signal_address())

                if msg.wa is not None:
                    msg.wa.sender_key_distribution_message = WAE2E_pb2.SenderKeyDistributionMessage(
                        group_id=receipt.chat.string(),
                        axolotl_sender_key_distribution_message=signal_skd_message.serialize()
                    )
                else:
                    fb_skdm = WAMsgTransport_pb2.MessageTransport_Protocol_Ancillary_SenderKeyDistributionMessage(
                        group_id=receipt.chat.string(),
                        axolotl_sender_key_distribution_message=signal_skd_message.serialize()
                    )
            except Exception as e:
                self.logger.warning(f"Failed to create sender key distribution message for retry of {message_id} in {receipt.chat} to {receipt.sender}: {e}")

        # Handle device sent message for messages from me
        elif receipt.is_from_me:
            if msg.wa is not None:
                msg.wa = WAE2E_pb2.Message(
                    device_sent_message=WAE2E_pb2.DeviceSentMessage(
                        destination_jid=receipt.chat.string(),
                        message=msg.wa
                    )
                )
            else:
                fb_dsm = WAMsgTransport_pb2.MessageTransport_Protocol_Integral_DeviceSentMessage(
                    destination_jid=receipt.chat.string()
                )

        # Pre-retry callback (if implemented)
        if self.client.pre_retry_callback is not None:
            try:
                should_proceed = self.client.pre_retry_callback(receipt, message_id, retry_count, msg)
                if not should_proceed:
                    self.logger.info(f"Pre-retry callback cancelled retry for {message_id}")
                    return None
            except Exception as e:
                self.logger.warning(f"Error in pre-retry callback: {e}")
                # Continue with retry even if callback fails

        # Serialize the message
        try:
            if msg.wa is not None:
                plaintext = msg.wa.SerializeToString()
            else:
                plaintext = msg.fb.SerializeToString()
                franking_hash = hmac.new(msg.fb.metadata.franking_key, plaintext, digestmod='sha256')
                franking_tag = franking_hash.digest()
        except Exception as e:
            return Exception(f"Failed to marshal message: {e}")

        # Check for prekey bundle
        has_keys = node.get_child("keys") is not None
        bundle = None

        if has_keys:
            try:
                bundle = node_to_pre_key_bundle(receipt.sender.device, node)
            except Exception as e:
                return Exception(f"Failed to read prekey bundle in retry receipt: {e}")
        else:
            # Check if we should recreate the session
            reason, recreate = await self.should_recreate_session(retry_count, receipt.sender)
            if recreate:
                self.logger.debug(f"Fetching prekeys for {receipt.sender} for handling retry receipt with no prekey bundle because {reason}")
                try:
                    keys = await self.client.fetch_pre_keys([receipt.sender])
                    if receipt.sender in keys:
                        bundle = keys[receipt.sender]
                    if not bundle:
                        return Exception(f"Didn't get prekey bundle for {receipt.sender}")
                except Exception as e:
                    return Exception(f"Failed to fetch prekeys: {e}")

        # Prepare encryption attributes
        enc_attrs = {}
        msg_attrs = {}

        if msg.wa is not None:
            # Get media type and message type from WA message
            media_type = self.client.get_media_type_from_message(msg.wa)
            msg_type = self.client.get_type_from_message(msg.wa)
            if media_type:
                msg_attrs["media_type"] = media_type
            msg_attrs["type"] = msg_type
        elif fb_consumer_msg is not None:
            # Get attributes from FB message
            attrs = self.client.get_attrs_from_fb_message(fb_consumer_msg)
            msg_attrs.update(attrs)
        else:
            msg_attrs["type"] = "text"

        if msg_attrs.get("media_type"):
            enc_attrs["mediatype"] = msg_attrs["media_type"]

        # Encrypt the message
        encrypted = None
        include_device_identity = False

        try:
            if msg.wa is not None:
                # Handle encryption identity for phone number
                encryption_identity = receipt.sender
                if receipt.sender.server == "s.whatsapp.net":
                    lid_for_pn = await self.client.store.get_lid_for_pn(receipt.sender)
                    if lid_for_pn and not lid_for_pn.is_empty():
                        await self.client.migrate_session_store(receipt.sender, lid_for_pn)
                        encryption_identity = lid_for_pn

                encrypted, include_device_identity, err = await self.client.encrypt_message_for_device(
                    plaintext, encryption_identity, bundle, enc_attrs
                )
            else:
                encrypted, err = await self.client.encrypt_message_for_device_v3(
                    WAMsgTransport_pb2.MessageTransport_Payload(
                        application_payload=WACommon_pb2.SubProtocol(
                            payload=plaintext,
                            version=3  # FB Message Application Version
                        ),
                        future_proof=WACommon_pb2.FutureProofBehavior.PLACEHOLDER
                    ),
                    fb_skdm, fb_dsm, receipt.sender, bundle, enc_attrs
                )

            if err:
                return Exception(f"Failed to encrypt message for retry: {err}")
        except Exception as e:
            return Exception(f"Failed to encrypt message for retry: {e}")

        # Add retry count to encrypted node
        encrypted.attributes["count"] = retry_count

        # Prepare message attributes
        attrs = {
            "to": node.attributes["from"],
            "type": msg_attrs["type"],
            "id": message_id,
            "t": timestamp.timestamp() if timestamp else 0,
        }

        if not receipt.is_group:
            attrs["device_fanout"] = False

        # Copy additional attributes from original node
        for attr_name in ["participant", "recipient", "edit"]:
            if attr_name in node.attributes:
                attrs[attr_name] = node.attributes[attr_name]

        # Prepare message content
        content = []
        if msg.wa is not None:
            content = self.client.get_message_content(
                encrypted, msg.wa, attrs, include_device_identity
            )
        else:
            content = [
                encrypted,
                Node(tag="franking", content=[
                    Node(tag="franking_tag", content=franking_tag)
                ])
            ]

        # Send the message
        try:
            await self.client.send_node(Node(
                tag="message",
                attributes=attrs,
                content=content
            ))
            self.logger.debug(f"Sent retry #{retry_count} for {receipt.chat}/{message_id} to {receipt.sender}")
            return None
        except Exception as e:
            return Exception(f"Failed to send retry message: {e}")

    def cancel_delayed_request_from_phone(self, msg_id: MessageID):
        """
        Cancel a delayed request for a message from the phone.

        Args:
            msg_id: The message ID
        """
        if not self.automatic_message_rerequest_from_phone:
            return

        cancel_pending_request = self.pending_phone_rerequests.get(msg_id)
        if cancel_pending_request:
            cancel_pending_request()

    async def delayed_request_message_from_phone(self, info: MessageInfo):
        """
        Request a message from the phone after a delay.

        Args:
            info: The message info
        """
        if not self.automatic_message_rerequest_from_phone:
            return

        # Check if we're already requesting this message
        if info.id in self.pending_phone_rerequests:
            return

        # Create a cancellable task
        cancel_event = asyncio.Event()

        def cancel():
            cancel_event.set()

        self.pending_phone_rerequests[info.id] = cancel

        try:
            # Wait for the delay or cancellation
            try:
                await asyncio.wait_for(cancel_event.wait(), timeout=REQUEST_FROM_PHONE_DELAY.total_seconds())
                self.logger.debug(f"Cancelled delayed request for message {info.id} from phone")
                return
            except asyncio.TimeoutError:
                pass

            # Request the message from the phone
            try:
                await self.client.send_message(
                    self.client.get_own_id().to_non_ad(),
                    self.client.build_unavailable_message_request(info.chat, info.sender, info.id),
                    peer=True
                )
                self.logger.debug(f"Requested message {info.id} from phone")
            except Exception as e:
                self.logger.warning(f"Failed to send request for unavailable message {info.id} to phone: {e}")
        finally:
            # Clean up
            if info.id in self.pending_phone_rerequests:
                del self.pending_phone_rerequests[info.id]

    def clear_delayed_message_requests(self):
        """Clear all pending delayed message requests."""
        for cancel in self.pending_phone_rerequests.values():
            cancel()

    async def send_retry_receipt(self, node: Node, info: MessageInfo, force_include_identity: bool = False):
        """
        Send a retry receipt for an incoming message.

        This method needs to:
        1. Track retry counts per message
        2. Generate prekeys and device identity when needed
        3. Build retry receipt node structure
        4. Send the retry receipt
        5. Handle delayed phone requests

        Args:
            node: The binary node containing the message
            info: The message info
            force_include_identity: Whether to force including identity information
        """
        id_str = node.attributes.get("id", "")

        # Check for retry count in the message
        children = node.get_children()
        retry_count_in_msg = 0
        if len(children) == 1 and children[0].tag == "enc":
            retry_count_in_msg = children[0].attr_getter().optional_int("count")

        # Track retry counts
        self.message_retries[id_str] = self.message_retries.get(id_str, 0) + 1
        retry_count = self.message_retries[id_str]

        # If the message is a retry response and we restarted in between, find the count from the message
        if retry_count == 1 and retry_count_in_msg > 0:
            retry_count = retry_count_in_msg + 1
            self.message_retries[id_str] = retry_count

        # Don't send too many retry receipts
        if retry_count >= 5:
            self.logger.warning(f"Not sending any more retry receipts for {id_str}")
            return

        # Start delayed request from phone on first retry
        if retry_count == 1:
            asyncio.create_task(self.delayed_request_message_from_phone(info))

        # Prepare registration ID bytes
        registration_id_bytes = struct.pack(">I", self.client.store.registration_id)

        # Prepare receipt attributes
        attrs = {
            "id": id_str,
            "type": "retry",
            "to": node.attributes.get("from", "")
        }

        # Copy recipient and participant attributes if present
        for attr_name in ["recipient", "participant"]:
            if attr_name in node.attributes:
                attrs[attr_name] = node.attributes[attr_name]

        # Build the receipt node
        payload = Node(
            tag="receipt",
            attributes=attrs,
            content=[
                Node(
                    tag="retry",
                    attributes={
                        "count": retry_count,
                        "id": id_str,
                        "t": node.attributes.get("t", ""),
                        "v": 1
                    }
                ),
                Node(tag="registration", content=registration_id_bytes)
            ]
        )

        # Include identity information if needed
        if retry_count > 1 or force_include_identity:
            try:
                # Generate a new prekey
                key = await self.client.store.pre_keys.gen_one_pre_key()
                if not key:
                    self.logger.error("Failed to get prekey for retry receipt")
                    return

                # Get device identity
                device_identity = self.client.store.account.SerializeToString()

                # Add keys node to payload
                keys_node = Node(
                    tag="keys",
                    content=[
                        Node(tag="type", content=bytes([5])),  # DJB_TYPE = 5 (curve25519)
                        Node(tag="identity", content=self.client.store.identity_key.pub),
                        key.to_node(),
                        self.client.store.signed_pre_key.to_node(),
                        Node(tag="device-identity", content=device_identity)
                    ]
                )

                payload.content.append(keys_node)
            except Exception as e:
                self.logger.error(f"Failed to prepare identity information for retry receipt: {e}")
                return

        # Send the receipt
        try:
            await self.client.send_node(payload)
            self.logger.debug(f"Sent retry receipt #{retry_count} for {id_str} to {attrs['to']}")
        except Exception as e:
            self.logger.error(f"Failed to send retry receipt for {id_str}: {e}")
