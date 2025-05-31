"""
Facebook message sending implementation for WhatsApp.

Port of whatsmeow/sendfb.go
"""
import asyncio
import hmac
import hashlib
import logging
import uuid
import random
import base64
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Union, TypeVar, Type, cast, Set
from enum import Enum, auto

from .generated.waArmadilloApplication import WAArmadilloApplication_pb2
from .generated.waConsumerApplication import WAConsumerApplication_pb2
from .generated.waMsgApplication import WAMsgApplication_pb2
from .generated.waMsgTransport import WAMsgTransport_pb2
from .generated.waCommon import WACommon_pb2
from .types.jid import JID
from .types.message import MessageID, MessageServerID
from .types.events import DecryptFailMode
from .types.message import EditAttribute
from .binary.node import Node, Attrs

# TODO: Verify import when signal protocol is ported
from .signal.groups import GroupSessionBuilder, GroupCipher
from .signal.protocol import SenderKeyName, CiphertextMessage
from .signal.session import SessionBuilder, SessionCipher
from .signal.serializer import ProtobufSerializer
from .signal.prekey import Bundle
from .signal.store import SignalStore

# Constants from the Go code
FB_MESSAGE_VERSION = 3
FB_MESSAGE_APPLICATION_VERSION = 2
FB_CONSUMER_MESSAGE_VERSION = 1
FB_ARMADILLO_MESSAGE_VERSION = 1

# Type aliases for better readability
RealMessageApplicationSub = Union[
    WAConsumerApplication_pb2.ConsumerApplication,
    WAArmadilloApplication_pb2.Armadillo
]

logger = logging.getLogger(__name__)

@dataclass
class MessageDebugTimings:
    """Timing information for message sending operations."""
    queue: float = 0.0
    get_participants: float = 0.0
    get_devices: float = 0.0
    peer_encrypt: float = 0.0
    group_encrypt: float = 0.0
    send: float = 0.0
    resp: float = 0.0
    retry: float = 0.0


@dataclass
class SendResponse:
    """Response from sending a message."""
    id: MessageID
    timestamp: int = 0
    server_id: MessageServerID = MessageServerID(0)
    debug_timings: MessageDebugTimings = field(default_factory=MessageDebugTimings)


@dataclass
class SendRequestExtra:
    """Extra parameters for send requests."""
    id: MessageID = ""
    timeout: float = 0.0
    peer: bool = False


@dataclass
class MessageAttrs:
    """Attributes for a message."""
    type: str = ""
    media_type: str = ""
    edit: EditAttribute = EditAttribute.EMPTY
    decrypt_fail: DecryptFailMode = DecryptFailMode.SHOW
    poll_type: str = ""


class SendFBError(Exception):
    """Base exception for FB message sending errors."""
    pass


class ClientIsNilError(SendFBError):
    """Error raised when client is nil."""
    def __init__(self):
        super().__init__("Client is nil")


class RecipientADJIDError(SendFBError):
    """Error raised when recipient is an AD JID."""
    def __init__(self):
        super().__init__("Can't send to AD JID")


class NotLoggedInError(SendFBError):
    """Error raised when not logged in."""
    def __init__(self):
        super().__init__("Not logged in")


class UnknownServerError(SendFBError):
    """Error raised when server is unknown."""
    def __init__(self, server: str):
        super().__init__(f"Unknown server: {server}")


class MessageTimedOutError(SendFBError):
    """Error raised when message times out."""
    def __init__(self):
        super().__init__("Message timed out")


class ServerReturnedError(SendFBError):
    """Error raised when server returns an error."""
    def __init__(self, code: int):
        super().__init__(f"Server returned error: {code}")


class NoSessionError(SendFBError):
    """Error raised when there's no session."""
    def __init__(self):
        super().__init__("No session")


class UntrustedIdentityError(SendFBError):
    """Error raised when there's an untrusted identity."""
    def __init__(self, jid: JID):
        super().__init__(f"Untrusted identity for {jid}")


class EncryptionError(SendFBError):
    """Error raised when encryption fails."""
    def __init__(self, message: str):
        super().__init__(f"Encryption failed: {message}")


class DeviceListError(SendFBError):
    """Error raised when there's an error getting the device list."""
    def __init__(self, message: str):
        super().__init__(f"Failed to get device list: {message}")


class GroupDataError(SendFBError):
    """Error raised when there's an error getting group data."""
    def __init__(self, jid: JID, message: str):
        super().__init__(f"Failed to get group data for {jid}: {message}")


class SendNodeError(SendFBError):
    """Error raised when there's an error sending a node."""
    def __init__(self, message: str):
        super().__init__(f"Failed to send node: {message}")


def pad_message(plaintext: Optional[bytes] = None) -> bytes:
    """Add padding to a message.

    Args:
        plaintext: The plaintext to pad. If None, only padding is returned.

    Returns:
        The padded plaintext
    """
    # Generate a random byte and mask it to ensure it's between 0-15
    pad_byte = random.randint(0, 255) & 0xf
    if pad_byte == 0:
        pad_byte = 0xf

    # Create padding bytes
    padding = bytes([pad_byte]) * pad_byte

    # If plaintext is provided, append padding to it
    if plaintext is not None:
        return plaintext + padding
    else:
        return padding


def participant_list_hash_v2(participants: List[JID]) -> str:
    """Calculate a hash of participant JIDs for group messages.

    Args:
        participants: List of participant JIDs

    Returns:
        A hash string in the format "2:<base64-encoded-hash>"
    """
    # Convert JIDs to strings and sort them
    participant_strings = [part.ad_string() for part in participants]
    participant_strings.sort()

    # Join all strings and calculate SHA-256 hash
    joined = "".join(participant_strings)
    hash_bytes = hashlib.sha256(joined.encode()).digest()

    # Return the first 6 bytes of the hash, base64-encoded
    return f"2:{base64.b64encode(hash_bytes[:6]).decode().rstrip('=')}"


def get_attrs_from_fb_consumer_message(msg: WAConsumerApplication_pb2.ConsumerApplication) -> MessageAttrs:
    """Extract message attributes from a consumer application message.

    Args:
        msg: The consumer application message

    Returns:
        The extracted message attributes
    """
    attrs = MessageAttrs()

    payload = msg.payload
    if not payload:
        attrs.type = "text"
        return attrs

    if payload.HasField("content"):
        content = payload.content

        # Handle different content types
        if (content.HasField("messageText") or
            content.HasField("extendedTextMessage")):
            attrs.type = "text"
        elif content.HasField("imageMessage"):
            attrs.media_type = "image"
        elif content.HasField("stickerMessage"):
            attrs.media_type = "sticker"
        elif content.HasField("viewOnceMessage"):
            view_once = content.viewOnceMessage
            if view_once.HasField("imageMessage"):
                attrs.media_type = "image"
            elif view_once.HasField("videoMessage"):
                attrs.media_type = "video"
        elif content.HasField("documentMessage"):
            attrs.media_type = "document"
        elif content.HasField("audioMessage"):
            if content.audioMessage.ptt:
                attrs.media_type = "ptt"
            else:
                attrs.media_type = "audio"
        elif content.HasField("videoMessage"):
            # TODO: gifPlayback?
            attrs.media_type = "video"
        elif content.HasField("locationMessage"):
            attrs.media_type = "location"
        elif content.HasField("liveLocationMessage"):
            attrs.media_type = "location"
        elif content.HasField("contactMessage"):
            attrs.media_type = "vcard"
        elif content.HasField("contactsArrayMessage"):
            attrs.media_type = "contact_array"
        elif content.HasField("pollCreationMessage"):
            attrs.poll_type = "creation"
            attrs.type = "poll"
        elif content.HasField("pollUpdateMessage"):
            attrs.poll_type = "vote"
            attrs.type = "poll"
            attrs.decrypt_fail = DecryptFailMode.HIDE
        elif content.HasField("reactionMessage"):
            attrs.type = "reaction"
            attrs.decrypt_fail = DecryptFailMode.HIDE
        elif content.HasField("editMessage"):
            attrs.edit = EditAttribute.MESSAGE_EDIT
            attrs.decrypt_fail = DecryptFailMode.HIDE

        if attrs.media_type and not attrs.type:
            attrs.type = "media"

    elif payload.HasField("applicationData"):
        app_data = payload.applicationData
        if app_data.HasField("revoke"):
            if app_data.revoke.key.fromMe:
                attrs.edit = EditAttribute.SENDER_REVOKE
            else:
                attrs.edit = EditAttribute.ADMIN_REVOKE
            attrs.decrypt_fail = DecryptFailMode.HIDE

    if not attrs.type:
        attrs.type = "text"

    return attrs


def get_attrs_from_fb_message(msg: RealMessageApplicationSub) -> MessageAttrs:
    """Extract message attributes from a message.

    Args:
        msg: The message

    Returns:
        The extracted message attributes
    """
    if isinstance(msg, WAConsumerApplication_pb2.ConsumerApplication):
        return get_attrs_from_fb_consumer_message(msg)
    elif isinstance(msg, WAArmadilloApplication_pb2.Armadillo):
        attrs = MessageAttrs()
        attrs.type = "media"
        attrs.media_type = "document"
        return attrs
    else:
        attrs = MessageAttrs()
        attrs.type = "text"
        return attrs


class Client:
    """Client for WhatsApp operations."""

    async def send_fb_message(
        self,
        ctx: Any,
        to: JID,
        message: RealMessageApplicationSub,
        metadata: Optional[WAMsgApplication_pb2.MessageApplication.Metadata] = None,
        extra: Optional[SendRequestExtra] = None
    ) -> SendResponse:
        """Send a Facebook message to the given JID.

        Args:
            ctx: The async context
            to: The recipient JID
            message: The message to send
            metadata: Optional metadata for the message
            extra: Optional extra parameters for the send request

        Returns:
            The send response

        Raises:
            ClientIsNilError: If client is nil
            RecipientADJIDError: If recipient is an AD JID
            NotLoggedInError: If not logged in
            UnknownServerError: If server is unknown
            MessageTimedOutError: If message times out
            ServerReturnedError: If server returns an error
        """
        if not self:
            raise ClientIsNilError()

        req = extra or SendRequestExtra()

        # Create subprotocol payload
        subproto = WAMsgApplication_pb2.MessageApplication.SubProtocolPayload()
        subproto.futureProof = WACommon_pb2.FutureProofBehavior.PLACEHOLDER

        if isinstance(message, WAConsumerApplication_pb2.ConsumerApplication):
            consumer_message = message.SerializeToString()
            subproto.consumerMessage.CopyFrom(WACommon_pb2.SubProtocol(
                payload=consumer_message,
                version=FB_CONSUMER_MESSAGE_VERSION
            ))
        elif isinstance(message, WAArmadilloApplication_pb2.Armadillo):
            armadillo_message = message.SerializeToString()
            subproto.armadillo.CopyFrom(WACommon_pb2.SubProtocol(
                payload=armadillo_message,
                version=FB_ARMADILLO_MESSAGE_VERSION
            ))
        else:
            raise TypeError(f"Unsupported message type {type(message)}")

        # Create metadata if not provided
        if metadata is None:
            metadata = WAMsgApplication_pb2.MessageApplication.Metadata()

        metadata.frankingVersion = 0
        metadata.frankingKey = bytes([0] * 32)  # Random bytes in Go

        msg_attrs = get_attrs_from_fb_message(message)

        # Create message application
        message_app_proto = WAMsgApplication_pb2.MessageApplication(
            payload=WAMsgApplication_pb2.MessageApplication.Payload(
                subProtocol=subproto
            ),
            metadata=metadata
        )

        message_app = message_app_proto.SerializeToString()

        # Calculate franking tag
        franking_hash = hmac.new(metadata.frankingKey, message_app, hashlib.sha256)
        franking_tag = franking_hash.digest()

        # Check recipient
        if to.device > 0 and not req.peer:
            raise RecipientADJIDError()

        own_id = self.get_own_id()
        if not own_id or own_id.is_empty():
            raise NotLoggedInError()

        # Set default timeout if not provided
        if req.timeout == 0:
            req.timeout = 60  # Default timeout in seconds

        # Generate message ID if not provided
        if not req.id:
            req.id = self.generate_message_id()

        resp = SendResponse(id=req.id)

        start = datetime.now()
        # TODO: Implement message send lock
        resp.debug_timings.queue = (datetime.now() - start).total_seconds()

        # TODO: Implement response waiting
        resp_chan = self.wait_response(req.id)

        if not req.peer:
            self.add_recent_message(to, req.id, None, message_app_proto)

        phash = ""
        data = None

        # Handle different server types
        if to.server == "g.us":  # GROUP_SERVER
            phash, data = await self.send_group_v3(
                ctx, to, own_id, req.id, message_app, msg_attrs, franking_tag, resp.debug_timings
            )
        elif to.server in ["s.whatsapp.net", "fb"]:  # DEFAULT_USER_SERVER, MESSENGER_SERVER
            if req.peer:
                raise NotImplementedError("Peer messages to fb are not yet supported")
            else:
                data, phash = await self.send_dm_v3(
                    ctx, to, own_id, req.id, message_app, msg_attrs, franking_tag, resp.debug_timings
                )
        else:
            raise UnknownServerError(to.server)

        start = datetime.now()
        if not data:
            # TODO: Implement response cancellation
            self.cancel_response(req.id, resp_chan)
            return resp

        # Wait for response with timeout and handle context cancellation
        resp_node = None
        try:
            # Create a task that waits for the response
            wait_task = asyncio.create_task(resp_chan)

            # Create a list of tasks to wait for
            wait_for = [wait_task]

            # Add a timeout task if needed
            timeout_task = None
            if req.timeout > 0:
                timeout_task = asyncio.create_task(asyncio.sleep(req.timeout))
                wait_for.append(timeout_task)

            # Wait for either the response or timeout
            done, pending = await asyncio.wait(
                wait_for,
                return_when=asyncio.FIRST_COMPLETED
            )

            # Check if the wait task completed
            if wait_task in done:
                resp_node = wait_task.result()
            # Check if we timed out
            elif timeout_task and timeout_task in done:
                logger.warning(f"Message {req.id} to {to} timed out after {req.timeout}s")
                raise MessageTimedOutError()
        except asyncio.CancelledError:
            logger.warning(f"Message {req.id} to {to} was cancelled")
            raise
        except Exception as e:
            logger.error(f"Error waiting for response to message {req.id}: {e}")
            raise
        finally:
            # Clean up any pending tasks
            if 'wait_task' in locals() and not wait_task.done():
                wait_task.cancel()
            if 'timeout_task' in locals() and timeout_task and not timeout_task.done():
                timeout_task.cancel()

            # Cancel the response if we didn't get a result
            if not resp_node:
                self.cancel_response(req.id, resp_chan)

        resp.debug_timings.resp = (datetime.now() - start).total_seconds()

        # TODO: Implement disconnect node check and retry
        if self.is_disconnect_node(resp_node):
            start = datetime.now()
            resp_node = await self.retry_frame("message send", req.id, data, resp_node, ctx, 0)
            resp.debug_timings.retry = (datetime.now() - start).total_seconds()

        # Process response
        if resp_node:
            resp.server_id = MessageServerID(resp_node.attrs.get("server_id", 0))
            resp.timestamp = int(resp_node.attrs.get("t", 0))

            error_code = int(resp_node.attrs.get("error", 0))
            if error_code != 0:
                raise ServerReturnedError(error_code)

            expected_phash = resp_node.attrs.get("phash", "")
            if expected_phash and phash != expected_phash:
                logger.warning(
                    f"Server returned different participant list hash when sending to {to}. "
                    "Some devices may not have received the message."
                )
                # TODO: Invalidate device list caches
                with self.group_cache_lock:
                    if to in self.group_cache:
                        del self.group_cache[to]

        return resp

    # Placeholder methods that would be implemented in the actual Client class
    def get_own_id(self) -> JID:
        """Get the client's own JID."""
        raise NotImplementedError()

    def generate_message_id(self) -> MessageID:
        """Generate a unique message ID."""
        raise NotImplementedError()

    def wait_response(self, id: MessageID) -> asyncio.Future:
        """Wait for a response with the given ID."""
        raise NotImplementedError()

    def add_recent_message(self, to: JID, id: MessageID,
                          data: Optional[bytes],
                          message: Any) -> None:
        """Add a message to the recent messages cache."""
        raise NotImplementedError()

    def cancel_response(self, id: MessageID, chan: asyncio.Future) -> None:
        """Cancel waiting for a response."""
        raise NotImplementedError()

    def is_disconnect_node(self, node: Optional[Node]) -> bool:
        """Check if a node is a disconnect node."""
        raise NotImplementedError()

    async def retry_frame(self, desc: str, id: MessageID,
                         data: bytes, resp_node: Optional[Node],
                         ctx: Any,
                         attempt: int) -> Optional[Node]:
        """Retry sending a frame."""
        raise NotImplementedError()

    async def send_group_v3(
        self,
        ctx: Any,
        to: JID,
        own_id: JID,
        id: MessageID,
        message_app: bytes,
        msg_attrs: MessageAttrs,
        franking_tag: bytes,
        timings: MessageDebugTimings
    ) -> Tuple[str, bytes]:
        """Send a message to a group using protocol v3.

        Args:
            ctx: The async context
            to: The group JID
            own_id: The sender's JID
            id: The message ID
            message_app: The serialized message application
            msg_attrs: The message attributes
            franking_tag: The franking tag
            timings: Timing information

        Returns:
            A tuple of (participant hash, serialized data)

        Raises:
            GroupDataError: If there's an error getting group data
            EncryptionError: If there's an error encrypting the message
            SendNodeError: If there's an error sending the node
        """
        # Get group metadata
        start = datetime.now()
        group_meta = None
        try:
            if to.server == "g.us":
                group_meta = await self.get_cached_group_data(ctx, to)
            timings.get_participants = (datetime.now() - start).total_seconds()
        except Exception as e:
            raise GroupDataError(to, str(e)) from e

        # Create sender key distribution message
        start = datetime.now()
        try:
            builder = GroupSessionBuilder(self.store, self.pb_serializer)
            sender_key_name = SenderKeyName(to.user_server(), own_id.signal_address())

            # Create signal SKDM
            signal_skdm = await builder.create(ctx, sender_key_name)

            # Create SKDM for transport
            skdm = WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage(
                groupID=to.user_server(),
                axolotlSenderKeyDistributionMessage=signal_skdm.serialize()
            )

            # Create cipher and encrypt message
            cipher = GroupCipher(builder, sender_key_name, self.store)

            # Create message transport
            message_transport = WAMsgTransport_pb2.MessageTransport(
                payload=WAMsgTransport_pb2.MessageTransport.Payload(
                    applicationPayload=WACommon_pb2.SubProtocol(
                        payload=message_app,
                        version=FB_MESSAGE_APPLICATION_VERSION
                    ),
                    futureProof=WACommon_pb2.FutureProofBehavior.PLACEHOLDER
                ),
                protocol=WAMsgTransport_pb2.MessageTransport.Protocol(
                    integral=WAMsgTransport_pb2.MessageTransport.Protocol.Integral(
                        padding=pad_message(),
                        dsm=None
                    ),
                    ancillary=WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary(
                        skdm=None,
                        deviceListMetadata=None,
                        icdc=None,
                        backupDirective=WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.BackupDirective(
                            messageID=id,
                            actionType=WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.BackupDirective.ActionType.UPSERT
                        )
                    )
                )
            )

            # Serialize and encrypt
            plaintext = message_transport.SerializeToString()
            encrypted = await cipher.encrypt(ctx, plaintext)
            ciphertext = encrypted.signed_serialize()
            timings.group_encrypt = (datetime.now() - start).total_seconds()
        except Exception as e:
            raise EncryptionError(str(e)) from e

        try:
            # Prepare message node
            node, all_devices = await self.prepare_message_node_v3(
                ctx, to, own_id, id, None, skdm, msg_attrs, franking_tag,
                group_meta.members, timings
            )

            # Calculate participant hash
            phash = participant_list_hash_v2(all_devices)
            node.attrs["phash"] = phash

            # Create SK message node
            sk_msg = Node(
                tag="enc",
                content=ciphertext,
                attrs={
                    "v": "3",
                    "type": "skmsg"
                }
            )

            if msg_attrs.media_type:
                sk_msg.attrs["mediatype"] = msg_attrs.media_type

            # Add SK message to node content
            if isinstance(node.content, list):
                node.content.append(sk_msg)
            else:
                node.content = [*node.get_children(), sk_msg]

            # Send node and get data
            start = datetime.now()
            data = await self.send_node_and_get_data(node)
            timings.send = (datetime.now() - start).total_seconds()

            return phash, data
        except DeviceListError:
            raise
        except EncryptionError:
            raise
        except Exception as e:
            raise SendNodeError(str(e)) from e

    async def prepare_message_node_v3(
        self,
        ctx: Any,
        to: JID,
        own_id: JID,
        id: MessageID,
        payload: Optional[WAMsgTransport_pb2.MessageTransport.Payload],
        skdm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage],
        msg_attrs: MessageAttrs,
        franking_tag: bytes,
        participants: List[JID],
        timings: MessageDebugTimings
    ) -> Tuple[Node, List[JID]]:
        """Prepare a message node for sending using protocol v3.

        This method handles the complex process of preparing a message for sending to one or more
        recipients. It performs the following key operations:

        1. Retrieves all devices for the participants
        2. Creates a message node with appropriate attributes
        3. Encrypts the message for each recipient device
        4. Adds metadata, franking, and trace information

        The method supports both direct messages (when payload is provided) and group messages
        (when skdm is provided). For direct messages, the payload contains the actual message
        content. For group messages, the payload is None and the message content is encrypted
        separately using the sender key.

        Args:
            ctx: The async context for cancellation and timeouts
            to: The recipient JID (user or group)
            own_id: The sender's JID
            id: The unique message ID
            payload: The message payload for direct messages (None for group messages)
            skdm: The sender key distribution message for group messages (None for direct messages)
            msg_attrs: Message attributes like type, media type, edit status, etc.
            franking_tag: The HMAC tag for message verification
            participants: The list of participant JIDs to send the message to
            timings: Object to track timing information for performance analysis

        Returns:
            A tuple containing:
            - The prepared message node ready to be sent
            - The list of all device JIDs that will receive the message

        Raises:
            DeviceListError: If there's an error retrieving the device list for participants
            EncryptionError: If there's an error during the encryption process
            asyncio.CancelledError: If the operation is cancelled
        """
        start = datetime.now()
        try:
            all_devices = await self.get_user_devices_context(ctx, participants)
            timings.get_devices = (datetime.now() - start).total_seconds()
        except Exception as e:
            raise DeviceListError(str(e))

        enc_attrs = {}
        attrs = {
            "id": id,
            "type": msg_attrs.type,
            "to": to.user_server(),
        }

        # Only include mediatype on DMs, for groups it's in the skmsg node
        if payload is not None and msg_attrs.media_type:
            enc_attrs["mediatype"] = msg_attrs.media_type

        if msg_attrs.edit:
            attrs["edit"] = msg_attrs.edit

        if msg_attrs.decrypt_fail:
            enc_attrs["decrypt-fail"] = msg_attrs.decrypt_fail

        # Create device sent message
        dsm = WAMsgTransport_pb2.MessageTransport.Protocol.Integral.DeviceSentMessage(
            destinationJID=to.user_server(),
            phash=""
        )

        # Encrypt message for all devices
        start = datetime.now()
        participant_nodes = await self.encrypt_message_for_devices_v3(
            ctx, all_devices, own_id, id, payload, skdm, dsm, enc_attrs
        )
        timings.peer_encrypt = (datetime.now() - start).total_seconds()

        # Create content nodes
        content = []
        content.append(Node(
            tag="participants",
            content=participant_nodes
        ))

        # Add meta node if needed
        meta_attrs = {}
        if msg_attrs.poll_type:
            meta_attrs["polltype"] = msg_attrs.poll_type
        if msg_attrs.decrypt_fail:
            meta_attrs["decrypt-fail"] = msg_attrs.decrypt_fail

        if meta_attrs:
            content.append(Node(
                tag="meta",
                attrs=meta_attrs
            ))

        # Add franking and trace nodes
        trace_request_id = uuid.uuid4()
        content.append(Node(
            tag="franking",
            content=[Node(
                tag="franking_tag",
                content=franking_tag
            )]
        ))
        content.append(Node(
            tag="trace",
            content=[Node(
                tag="request_id",
                content=trace_request_id.bytes
            )]
        ))

        # Create and return the message node
        return Node(
            tag="message",
            attrs=attrs,
            content=content
        ), all_devices

    async def encrypt_message_for_devices_v3(
        self,
        ctx: Any,
        all_devices: List[JID],
        own_id: JID,
        id: MessageID,
        payload: Optional[WAMsgTransport_pb2.MessageTransport.Payload],
        skdm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage],
        dsm: WAMsgTransport_pb2.MessageTransport.Protocol.Integral.DeviceSentMessage,
        enc_attrs: Dict[str, str]
    ) -> List[Node]:
        """Encrypt a message for all recipient devices.

        Args:
            ctx: The async context
            all_devices: The list of all recipient devices
            own_id: The sender's JID
            id: The message ID
            payload: The message payload
            skdm: The sender key distribution message
            dsm: The device sent message
            enc_attrs: Additional encryption attributes

        Returns:
            A list of participant nodes with encrypted content
        """
        participant_nodes = []
        retry_devices = []

        # Encrypt message for each device
        for jid in all_devices:
            dsm_for_device = None
            if jid.user == own_id.user:
                if jid == own_id:
                    continue
                dsm_for_device = dsm

            try:
                encrypted = await self.encrypt_message_for_device_and_wrap_v3(
                    ctx, payload, skdm, dsm_for_device, jid, None, enc_attrs
                )
                participant_nodes.append(encrypted)
            except NoSessionError:
                retry_devices.append(jid)
            except Exception as e:
                # TODO: Return these errors if it's a fatal one (like context cancellation or database)
                logger.warning(f"Failed to encrypt {id} for {jid}: {e}")
                continue

        # Retry encryption for devices without sessions
        if retry_devices:
            try:
                bundles = await self.fetch_pre_keys(ctx, retry_devices)
                for jid in retry_devices:
                    if jid not in bundles or bundles[jid].err:
                        if jid in bundles:
                            logger.warning(f"Failed to fetch prekey for {jid}: {bundles[jid].err}")
                        continue

                    dsm_for_device = None
                    if jid.user == own_id.user:
                        dsm_for_device = dsm

                    try:
                        encrypted = await self.encrypt_message_for_device_and_wrap_v3(
                            ctx, payload, skdm, dsm_for_device, jid, bundles[jid].bundle, enc_attrs
                        )
                        participant_nodes.append(encrypted)
                    except Exception as e:
                        # TODO: Return these errors if it's a fatal one (like context cancellation or database)
                        logger.warning(f"Failed to encrypt {id} for {jid} (retry): {e}")
                        continue
            except Exception as e:
                logger.warning(f"Failed to fetch prekeys for {retry_devices} to retry encryption: {e}")

        return participant_nodes

    async def encrypt_message_for_device_and_wrap_v3(
        self,
        ctx: Any,
        payload: Optional[WAMsgTransport_pb2.MessageTransport.Payload],
        skdm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage],
        dsm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Integral.DeviceSentMessage],
        to: JID,
        bundle: Any,  # Should be prekey.Bundle when implemented
        enc_attrs: Dict[str, str]
    ) -> Node:
        """Encrypt a message for a specific device and wrap it in a node.

        Args:
            ctx: The async context
            payload: The message payload
            skdm: The sender key distribution message
            dsm: The device sent message
            to: The recipient JID
            bundle: The prekey bundle
            enc_attrs: Additional encryption attributes

        Returns:
            A node containing the encrypted message
        """
        node = await self.encrypt_message_for_device_v3(
            ctx, payload, skdm, dsm, to, bundle, enc_attrs
        )

        return Node(
            tag="to",
            attrs={"jid": to.user_server()},
            content=[node]
        )

    async def encrypt_message_for_device_v3(
        self,
        ctx: Any,
        payload: Optional[WAMsgTransport_pb2.MessageTransport.Payload],
        skdm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage],
        dsm: Optional[WAMsgTransport_pb2.MessageTransport.Protocol.Integral.DeviceSentMessage],
        to: JID,
        bundle: Any,  # Should be prekey.Bundle when implemented
        extra_attrs: Dict[str, str]
    ) -> Node:
        """Encrypt a message for a specific device using the Signal protocol.

        This method handles the end-to-end encryption of a message for a specific recipient device.
        It performs the following key operations:

        1. Creates or retrieves a Signal session for the recipient
        2. Processes a prekey bundle if provided (for new sessions)
        3. Creates a message transport with the payload, padding, and other metadata
        4. Encrypts the message using the Signal protocol
        5. Creates a node with the encrypted content and appropriate attributes

        The encryption process uses the Signal protocol to ensure end-to-end encryption with
        perfect forward secrecy. If no session exists for the recipient and no bundle is provided,
        a NoSessionError is raised. If there's an issue with the recipient's identity, an
        UntrustedIdentityError is raised.

        Args:
            ctx: The async context for cancellation and timeouts
            payload: The message payload containing the content to encrypt (can be None for group messages)
            skdm: The sender key distribution message for group chats (None for direct messages)
            dsm: The device sent message metadata for messages sent to other devices of the same user
            to: The recipient device JID
            bundle: The prekey bundle for establishing a new session (None if session already exists)
            extra_attrs: Additional attributes to include in the encryption node

        Returns:
            A binary node containing the encrypted message with appropriate attributes

        Raises:
            NoSessionError: If there's no session for the recipient and no bundle is provided
            UntrustedIdentityError: If the recipient's identity can't be trusted
            EncryptionError: If there's an error during the encryption process
            asyncio.CancelledError: If the operation is cancelled
        """
        # TODO: Implement actual encryption with Signal protocol
        # This is a placeholder implementation

        try:
            # Create session builder
            logger.debug(f"Creating session builder for {to}")
            builder = SessionBuilder(self.store, to.signal_address(), self.pb_serializer)

            if bundle is not None:
                logger.debug(f"Processing prekey bundle for {to}")
                try:
                    await builder.process_bundle(ctx, bundle)
                except Exception as e:
                    error_msg = str(e).lower()
                    if self.auto_trust_identity and "untrusted identity" in error_msg:
                        logger.warning(f"Got untrusted identity error for {to}, clearing stored identity and retrying")
                        try:
                            await self.clear_untrusted_identity(ctx, to)
                            await builder.process_bundle(ctx, bundle)
                            logger.info(f"Successfully processed bundle for {to} after clearing identity")
                        except Exception as e2:
                            logger.error(f"Failed to process bundle for {to} after clearing identity: {e2}")
                            raise UntrustedIdentityError(to) from e2
                    elif "no prekey" in error_msg:
                        logger.error(f"No prekey found in bundle for {to}")
                        raise NoSessionError() from e
                    elif "invalid signature" in error_msg:
                        logger.error(f"Invalid signature in bundle for {to}")
                        raise EncryptionError(f"Invalid signature in bundle for {to}") from e
                    else:
                        logger.error(f"Failed to process bundle for {to}: {e}")
                        raise UntrustedIdentityError(to) from e
            elif not await self.store.contains_session(ctx, to.signal_address()):
                logger.warning(f"No session found for {to} and no bundle provided")
                raise NoSessionError()

            # Create cipher
            logger.debug(f"Creating cipher for {to}")
            cipher = SessionCipher(builder, to.signal_address())
        except NoSessionError:
            logger.warning(f"No session available for {to}")
            raise
        except UntrustedIdentityError as e:
            logger.error(f"Untrusted identity for {to}: {e}")
            raise
        except asyncio.CancelledError:
            logger.warning(f"Encryption for {to} was cancelled")
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating session for {to}: {e}")
            raise EncryptionError(f"Failed to create session for {to}: {str(e)}") from e

        # Create message transport
        message_transport = WAMsgTransport_pb2.MessageTransport(
            payload=payload,
            protocol=WAMsgTransport_pb2.MessageTransport.Protocol(
                integral=WAMsgTransport_pb2.MessageTransport.Protocol.Integral(
                    padding=pad_message(),
                    dsm=dsm
                ),
                ancillary=WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary(
                    skdm=skdm,
                    deviceListMetadata=None,
                    icdc=None,
                    backupDirective=None
                )
            )
        )

        # Serialize and encrypt
        try:
            logger.debug(f"Serializing message transport for {to}")
            plaintext = message_transport.SerializeToString()

            logger.debug(f"Encrypting message for {to}")
            ciphertext = await cipher.encrypt(ctx, plaintext)
            logger.debug(f"Successfully encrypted message for {to}")
        except asyncio.CancelledError:
            logger.warning(f"Message encryption for {to} was cancelled")
            raise
        except Exception as e:
            error_msg = str(e).lower()
            if "session not found" in error_msg:
                logger.error(f"Session not found for {to} during encryption")
                raise NoSessionError() from e
            elif "untrusted identity" in error_msg:
                logger.error(f"Untrusted identity for {to} during encryption")
                raise UntrustedIdentityError(to) from e
            elif "invalid key" in error_msg:
                logger.error(f"Invalid key for {to} during encryption: {e}")
                raise EncryptionError(f"Invalid key for {to}: {str(e)}") from e
            else:
                logger.error(f"Failed to encrypt message for {to}: {e}")
                raise EncryptionError(f"Failed to encrypt message for {to}: {str(e)}") from e

        # Create encryption attributes
        enc_attrs = {
            "v": str(FB_MESSAGE_VERSION),
            "type": "msg"
        }

        if ciphertext.get_type() == "prekey":
            enc_attrs["type"] = "pkmsg"

        # Add extra attributes
        for key, value in extra_attrs.items():
            enc_attrs[key] = value

        # Create and return node
        return Node(
            tag="enc",
            attrs=enc_attrs,
            content=ciphertext.serialize()
        )

    async def send_dm_v3(
        self,
        ctx: Any,
        to: JID,
        own_id: JID,
        id: MessageID,
        message_app: bytes,
        msg_attrs: MessageAttrs,
        franking_tag: bytes,
        timings: MessageDebugTimings
    ) -> Tuple[bytes, str]:
        """Send a direct message using protocol v3.

        Args:
            ctx: The async context
            to: The recipient JID
            own_id: The sender's JID
            id: The message ID
            message_app: The serialized message application
            msg_attrs: The message attributes
            franking_tag: The franking tag
            timings: Timing information

        Returns:
            A tuple of (serialized data, participant hash)

        Raises:
            DeviceListError: If there's an error getting the device list
            EncryptionError: If there's an error encrypting the message
            SendNodeError: If there's an error sending the node
        """
        try:
            logger.debug(f"Creating payload for DM to {to}")
            # Create payload
            payload = WAMsgTransport_pb2.MessageTransport.Payload(
                applicationPayload=WACommon_pb2.SubProtocol(
                    payload=message_app,
                    version=FB_MESSAGE_APPLICATION_VERSION
                ),
                futureProof=WACommon_pb2.FutureProofBehavior.PLACEHOLDER
            )

            logger.debug(f"Preparing message node for DM to {to}")
            # Prepare message node
            try:
                node, all_devices = await self.prepare_message_node_v3(
                    ctx, to, own_id, id, payload, None, msg_attrs, franking_tag,
                    [to, own_id.to_non_ad()], timings
                )
            except DeviceListError as e:
                logger.error(f"Failed to get device list for DM to {to}: {e}")
                raise
            except EncryptionError as e:
                logger.error(f"Encryption error preparing message node for DM to {to}: {e}")
                raise
            except asyncio.CancelledError:
                logger.warning(f"Message preparation for DM to {to} was cancelled")
                raise
            except Exception as e:
                logger.error(f"Unexpected error preparing message node for DM to {to}: {e}")
                raise SendNodeError(f"Failed to prepare message node for {to}: {str(e)}") from e

            logger.debug(f"Sending node for DM to {to}")
            # Send node and get data
            start = datetime.now()
            try:
                data = await self.send_node_and_get_data(node)
                timings.send = (datetime.now() - start).total_seconds()
                logger.debug(f"Successfully sent DM to {to} in {timings.send:.3f}s")
            except asyncio.CancelledError:
                logger.warning(f"Sending DM to {to} was cancelled")
                raise
            except Exception as e:
                logger.error(f"Failed to send node for DM to {to}: {e}")
                raise SendNodeError(f"Failed to send message to {to}: {str(e)}") from e

            # Calculate participant hash
            phash = participant_list_hash_v2(all_devices)
            logger.debug(f"Calculated participant hash for DM to {to}: {phash}")

            # Return data and participant hash
            return data, phash
        except DeviceListError:
            # Already logged and raised in inner try block
            raise
        except EncryptionError:
            # Already logged and raised in inner try block
            raise
        except asyncio.CancelledError:
            # Already logged and raised in inner try blocks
            raise
        except Exception as e:
            logger.error(f"Unexpected error sending DM to {to}: {e}")
            raise SendNodeError(f"Failed to send DM to {to}: {str(e)}") from e
