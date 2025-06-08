"""
Facebook/Meta message sending functionality for WhatsApp.

This module provides functions for sending Facebook-style (v3) messages,
which use a different protocol structure than traditional WhatsApp messages.

Port of whatsmeow/sendfb.go
"""

import hashlib
import hmac
import os
import time
import uuid
from datetime import timedelta
from typing import Union, Optional, List, Tuple, TYPE_CHECKING
from dataclasses import dataclass

from . import request, group, send, retry, user
from .binary.attrs import Attrs
from .binary.node import Node
from .exceptions import ErrClientIsNil, ErrRecipientADJID, ErrNotLoggedIn, ErrUnknownServer, ErrMessageTimedOut, \
    ErrServerReturnedError
from .generated import waCommon, waConsumerApplication, waArmadilloApplication, waMsgApplication, waMsgTransport
from .generated.waCommon import WACommon_pb2
from .generated.waMsgApplication import WAMsgApplication_pb2

from .send import SendRequestExtra, MessageDebugTimings, SendResponse

if TYPE_CHECKING:
    from .client import Client
    from .generated.waConsumerApplication.WAConsumerApplication_pb2 import ConsumerApplication
    from .generated.waArmadilloApplication.WAArmadilloApplication_pb2 import Armadillo
    from .generated.waMsgApplication.WAMsgApplication_pb2 import MessageApplication
    from .generated.waMsgTransport.WAMsgTransport_pb2 import MessageTransport
    from .types.message import MessageID, EditAttribute, MessageServerID
    from .types.jid import JID, GROUP_SERVER, DEFAULT_USER_SERVER, MESSENGER_SERVER
    from .types.events import DecryptFailMode

# Constants matching Go implementation exactly
FB_MESSAGE_VERSION = 3
FB_MESSAGE_APPLICATION_VERSION = 2
FB_CONSUMER_MESSAGE_VERSION = 1
FB_ARMADILLO_MESSAGE_VERSION = 1

# Type alias for supported message types - matches Go's armadillo.RealMessageApplicationSub
RealMessageApplicationSub = Union['ConsumerApplication', 'Armadillo']


@dataclass
class MessageAttrs:
    """Message attributes extracted from message content - matches Go's messageAttrs struct."""
    type: str = ""
    media_type: str = ""
    edit: Optional['EditAttribute'] = None
    decrypt_fail: Optional['DecryptFailMode'] = None
    poll_type: str = ""


async def send_fb_message(
    client: 'Client',
    to: 'JID',
    message: RealMessageApplicationSub,
    metadata: Optional['MessageApplication.Metadata'] = None,
    *extra: SendRequestExtra
) -> Tuple[SendResponse, Optional[Exception]]:
    """
    Port of Go method SendFBMessage from the WhatsApp client.

    Sends the given v3 message to the given JID.

    Args:
        client: The WhatsApp client instance
        to: Target JID to send message to
        message: The message payload to send
        metadata: Optional message metadata
        extra: Optional extra send request parameters (max 1)

    Returns:
        Tuple containing (SendResponse, error)
    """
    # TODO: Review Client implementation
    # TODO: Review SendRequestExtra implementation
    # TODO: Review SendResponse implementation
    # TODO: Review get_attrs_from_fb_message implementation
    # TODO: Review random_bytes implementation

    resp = SendResponse()

    if client is None:
        return resp, ErrClientIsNil

    # Handle extra parameters - matches Go logic exactly
    if len(extra) > 1:
        return resp, Exception("only one extra parameter may be provided to SendMessage")
    elif len(extra) == 1:
        req = extra[0]
    else:
        req = SendRequestExtra()  # Default empty struct

    # Build sub protocol payload - matches Go implementation
    subproto = WAMsgApplication_pb2.MessageApplication.SubProtocolPayload()
    subproto.future_proof = waCommon.WACommon_pb2.FutureProofBehavior.PLACEHOLDER

    # Type switch matching Go exactly
    if isinstance(message, waConsumerApplication.WAConsumerApplication_pb2.ConsumerApplication):
        try:
            consumer_message = message.SerializeToString()
        except Exception as e:
            return resp, Exception(f"failed to marshal consumer message: {e}")

        subproto.consumerMessage.CopyFrom(waCommon.WACommon_pb2.SubProtocol(
            payload=consumer_message,
            version=FB_CONSUMER_MESSAGE_VERSION
        ))

    elif isinstance(message, waArmadilloApplication.WAArmadilloApplication_pb2.Armadillo):
        try:
            armadillo_message = message.SerializeToString()
        except Exception as e:
            return resp, Exception(f"failed to marshal armadillo message: {e}")

        subproto.armadillo.CopyFrom(waCommon.WACommon_pb2.SubProtocol(
            payload=armadillo_message,
            version=FB_ARMADILLO_MESSAGE_VERSION
        ))
    else:
        return resp, Exception(f"unsupported message type {type(message)}")

    # Set up metadata - matches Go logic
    if metadata is None:
        metadata = waMsgApplication.WAMsgApplication_pb2.MessageApplication.Metadata()

    metadata.franking_version = 0
    metadata.franking_key = os.urandom(32)

    msg_attrs = get_attrs_from_fb_message(message)  # TODO: Review method implementation

    # Build message application proto - matches Go structure
    message_app_proto = waMsgApplication.WAMsgApplication_pb2.MessageApplication()
    message_app_proto.payload.subProtocol.CopyFrom(subproto)
    message_app_proto.metadata.CopyFrom(metadata)

    try:
        message_app = message_app_proto.SerializeToString()
    except Exception as e:
        return resp, Exception(f"failed to marshal message application: {e}")

    # Calculate franking tag - matches Go hmac calculation
    franking_hash = hmac.new(metadata.franking_key, message_app, hashlib.sha256)
    franking_tag = franking_hash.digest()

    # Validation - matches Go checks exactly
    if to.device > 0 and not req.peer:
        return resp, ErrRecipientADJID

    own_id = client.get_own_id()  # TODO: Review method implementation
    if own_id.is_empty():  # TODO: Review JID.is_empty implementation
        return resp, ErrNotLoggedIn

    if req.timeout == 0:
        req.timeout = request.DEFAULT_REQUEST_TIMEOUT  # TODO: Review constant location

    if len(req.id) == 0:
        req.id = send.generate_message_id(client)  # TODO: Review method implementation

    resp.id = req.id

    # Timing and locking - matches Go implementation
    start = time.time()
    client.message_send_lock.acquire()  # TODO: Review lock implementation
    resp.debug_timings.queue = time.time() - start

    try:
        resp_chan = await request.wait_response(client, req.id)  # TODO: Review method implementation

        if not req.peer:
            retry.add_recent_message(client, to, req.id, None, message_app_proto)  # TODO: Review method implementation

        phash = ""
        data = b""
        err = None

        # Server type switch - matches Go exactly
        if to.server == GROUP_SERVER:
            phash, data, err = send_group_v3(
                client, to, own_id, req.id, message_app, msg_attrs, franking_tag, resp.debug_timings
            )  # TODO: Review method implementation
        elif to.server in [DEFAULT_USER_SERVER, MESSENGER_SERVER]:
            if req.peer:
                err = Exception("peer messages to fb are not yet supported")
            else:
                data, phash, err = send_dm_v3(
                    client, to, own_id, req.id, message_app, msg_attrs, franking_tag, resp.debug_timings
                )  # TODO: Review method implementation
        else:
            err = Exception(f"{ErrUnknownServer} {to.server}")

        start = time.time()
        if err is not None:
            await request.cancel_response(client, req.id, resp_chan)  # TODO: Review method implementation
            return resp, err

        # Response handling with timeout - matches Go select statement
        resp_node = None
        timeout_chan = None

        if req.timeout > timedelta(0):
            timeout_chan = time.time() + req.timeout

        # This simulates Go's select statement behavior
        # TODO: Review proper channel/timeout implementation for Python
        try:
            if timeout_chan and time.time() >= timeout_chan:
                client.cancel_response(req.id, resp_chan)
                return resp, ErrMessageTimedOut
            # elif ctx and ctx.done():  # TODO: Review context implementation
            #     client.cancel_response(req.id, resp_chan)
            #     return resp, ctx.err()
            else:
                resp_node = next(resp_chan)  # TODO: Review channel implementation
        except Exception as e:
            client.cancel_response(req.id, resp_chan)
            return resp, e

        resp.debug_timings.resp = time.time() - start

        # Disconnect handling - matches Go logic
        if client.is_disconnect_node(resp_node):  # TODO: Review method implementation
            start = time.time()
            resp_node, err = request.retry_frame(client, "message send", req.id, data, resp_node, 0)
            resp.debug_timings.retry = time.time() - start
            if err is not None:
                return resp, err

        # Parse response - matches Go response parsing
        ag = resp_node.attr_getter()  # TODO: Review Node.attr_getter implementation
        resp.server_id = MessageServerID(ag.optional_int("server_id"))
        resp.timestamp = ag.unix_time("t")

        error_code = ag.int("error")
        if error_code != 0:
            return resp, Exception(f"{ErrServerReturnedError} {error_code}")

        expected_phash = ag.optional_string("phash")
        if len(expected_phash) > 0 and phash != expected_phash:
            client.log.warnf(  # TODO: Review logger implementation
                "Server returned different participant list hash when sending to %s. Some devices may not have received the message.",
                to
            )
            # TODO also invalidate device list caches
            client.group_cache_lock.acquire()  # TODO: Review lock implementation
            try:
                if to in client.group_cache:
                    del client.group_cache[to]
            finally:
                client.group_cache_lock.release()

        return resp, None

    finally:
        client.message_send_lock.release()


def send_group_v3(
    client: 'Client',
    to: 'JID',
    own_id: 'JID',
    id: 'MessageID',
    message_app: bytes,
    msg_attrs: MessageAttrs,
    franking_tag: bytes,
    timings: MessageDebugTimings
) -> Tuple[str, bytes, Optional[Exception]]:
    """
    Port of Go method sendGroupV3 from client.go.

    Sends a v3 message to a group using Signal's sender key encryption.

    Args:
        client: The WhatsApp client instance
        ctx: Context for cancellation
        to: Target group JID
        own_id: Own user JID
        id: Message ID
        message_app: Serialized message application payload
        msg_attrs: Message attributes
        franking_tag: Franking tag for the message
        timings: Debug timing collector

    Returns:
        Tuple containing (participant_hash, node_data, error)
    """
    # TODO: Review Client implementation
    # TODO: Review GroupMetaCache implementation
    # TODO: Review GroupSessionBuilder implementation
    # TODO: Review GroupCipher implementation
    # TODO: Review SenderKeyName implementation
    # TODO: Review pad_message implementation
    # TODO: Review participant_list_hash_v2 implementation
    # TODO: Review prepare_message_node_v3 implementation

    group_meta = None
    err = None

    start = time.time()
    if to.server == client.types.GroupServer:  # TODO: Review types implementation
        group_meta, err = group.get_cached_group_data(client, to)
        if err is not None:
            return "", b"", Exception(f"failed to get group members: {err}")

    timings.get_participants = time.time() - start

    start = time.time()

    # Create group session builder - matches Go libsignal usage
    builder = GroupSessionBuilder(client.store, client.pb_serializer)  # TODO: Review store and serializer
    sender_key_name = SenderKeyName(to.string(), own_id.signal_address())  # TODO: Review JID methods

    try:
        signal_skd_message = builder.create(ctx, sender_key_name)
    except Exception as e:
        return "", b"", Exception(f"failed to create sender key distribution message to send {id} to {to}: {e}")

    # Create sender key distribution message proto - matches Go structure
    skdm = waMsgTransport.WAMsgTransport_pb2.MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage()
    skdm.group_id = to.string()
    skdm.axolotl_sender_key_distribution_message = signal_skd_message.serialize()

    # Create group cipher and encrypt - matches Go cipher usage
    cipher = GroupCipher(builder, sender_key_name, client.store)

    # Build message transport proto - matches Go structure exactly
    message_transport = waMsgTransport.WAMsgTransport_pb2.MessageTransport()

    # Set payload
    message_transport.payload.applicationPayload.payload = message_app
    message_transport.payload.applicationPayload.version = client.FB_MESSAGE_APPLICATION_VERSION  # TODO: Review constant
    message_transport.payload.future_proof = waCommon.WACommon_pb2.FutureProofBehavior.PLACEHOLDER

    # Set protocol integral
    message_transport.protocol.integral.padding = client.pad_message(None)  # TODO: Review pad_message implementation
    message_transport.protocol.integral.dsm = None  # Explicitly set to None like Go nil

    # Set protocol ancillary
    message_transport.protocol.ancillary.skdm = None  # Will be set in prepareMessageNodeV3
    message_transport.protocol.ancillary.device_list_metadata = None
    message_transport.protocol.ancillary.icdc = None

    # Set backup directive - matches Go structure
    message_transport.protocol.ancillary.backup_directive.message_id = id
    message_transport.protocol.ancillary.backup_directive.action_type = (
        waMsgTransport.MessageTransport_Protocol_Ancillary_BackupDirective.UPSERT
    )

    try:
        plaintext = message_transport.SerializeToString()
    except Exception as e:
        return "", b"", Exception(f"failed to marshal message transport: {e}")

    try:
        encrypted = cipher.encrypt(ctx, plaintext)
    except Exception as e:
        return "", b"", Exception(f"failed to encrypt group message to send {id} to {to}: {e}")

    ciphertext = encrypted.signed_serialize()
    timings.group_encrypt = time.time() - start

    # Prepare message node - matches Go call exactly
    node, all_devices, err = client.prepare_message_node_v3(
        ctx, to, own_id, id, None, skdm, msg_attrs, franking_tag, group_meta.members, timings
    )
    if err is not None:
        return "", b"", err

    # Calculate participant hash and set on node
    phash = client.participant_list_hash_v2(all_devices)  # TODO: Review method implementation
    node.attrs["phash"] = phash

    # Create encrypted message node - matches Go structure exactly
    sk_msg = Node(
        tag="enc",
        content=ciphertext,
        attrs=Attrs({"v": "3", "type": "skmsg"})
    )

    if msg_attrs.media_type != "":
        sk_msg.attrs["mediatype"] = msg_attrs.media_type

    # Append to node content - matches Go logic
    children = node.get_children()  # TODO: Review Node.get_children implementation
    children.append(sk_msg)
    node.content = children

    # Send node and get response data
    start = time.time()
    try:
        data = client.send_node_and_get_data(node)  # TODO: Review method implementation
    except Exception as e:
        return "", b"", Exception(f"failed to send message node: {e}")

    timings.send = time.time() - start

    return phash, data, None


def send_dm_v3(
    client: 'Client',
    to: 'JID',
    own_id: 'JID',
    id: 'MessageID',
    message_app: bytes,
    msg_attrs: MessageAttrs,
    franking_tag: bytes,
    timings: MessageDebugTimings
) -> Tuple[bytes, str, Optional[Exception]]:
    """
    Port of Go method sendDMV3 from client.go.

    Sends a v3 message to a direct message chat.

    Args:
        client: The WhatsApp client instance
        to: Target user JID
        own_id: Own user JID
        id: Message ID
        message_app: Serialized message application payload
        msg_attrs: Message attributes
        franking_tag: Franking tag for the message
        timings: Debug timing collector

    Returns:
        Tuple containing (node_data, participant_hash, error)
    """
    # TODO: Review Client implementation
    # TODO: Review prepare_message_node_v3 implementation
    # TODO: Review participant_list_hash_v2 implementation

    # Create payload - matches Go structure exactly
    payload = waMsgTransport.WAMsgTransport_pb2.MessageTransport.Payload()
    payload.applicationPayload.payload = message_app
    payload.applicationPayload.version = FB_MESSAGE_APPLICATION_VERSION  # TODO: Review constant location
    payload.future_proof = waCommon.WACommon_pb2.FutureProofBehavior.PLACEHOLDER

    # Create participant list - matches Go slice exactly
    participants = [to, own_id.to_non_ad()]  # TODO: Review JID.to_non_ad implementation

    # Prepare message node - matches Go call exactly
    node, all_devices, err = prepare_message_node_v3(
        client, to, own_id, id, payload, None, msg_attrs, franking_tag, participants, timings
    )
    if err is not None:
        return b"", "", err

    # Send node and measure timing - matches Go implementation
    start = time.time()
    try:
        data = client.send_node_and_get_data(node)  # TODO: Review method implementation
    except Exception as e:
        return b"", "", Exception(f"failed to send message node: {e}")

    timings.send = time.time() - start

    # Return in Go order: data, hash, error
    return data, participant_list_hash_v2(all_devices), None  # TODO: Review method implementation

def get_attrs_from_fb_message(msg: RealMessageApplicationSub) -> MessageAttrs:
    """Extract message attributes from a Facebook message.

    This function exactly matches the Go getAttrsFromFBMessage function.
    """
    # Use isinstance instead of __class__.__name__ for proper type checking
    if hasattr(msg, '__class__'):
        if 'ConsumerApplication' in str(type(msg)):
            return get_attrs_from_fb_consumer_message(msg)
        elif 'Armadillo' in str(type(msg)):
            attrs = MessageAttrs()
            attrs.type = "media"
            attrs.media_type = "document"
            return attrs

    # Default case
    attrs = MessageAttrs()
    attrs.type = "text"
    return attrs

def get_attrs_from_fb_consumer_message(msg: 'ConsumerApplication') -> MessageAttrs:
    """Extract message attributes from a consumer application message.

    This function exactly matches the Go getAttrsFromFBConsumerMessage function.
    """
    attrs = MessageAttrs()

    payload = msg.payload
    if not payload:
        attrs.type = "text"  # Default fallback
        return attrs

    # Handle different payload types
    if hasattr(payload, 'content') and payload.content:
        content = payload.content
        if hasattr(content, 'content'):
            content_type = content.content

            # Check content types - matches Go switch statement exactly
            if (hasattr(content_type, 'message_text') or
                hasattr(content_type, 'extended_text_message')):
                attrs.type = "text"

            elif hasattr(content_type, 'image_message'):
                attrs.media_type = "image"

            elif hasattr(content_type, 'sticker_message'):
                attrs.media_type = "sticker"

            elif hasattr(content_type, 'view_once_message'):
                view_once = content_type.view_once_message
                if hasattr(view_once, 'image_message'):
                    attrs.media_type = "image"
                elif hasattr(view_once, 'video_message'):
                    attrs.media_type = "video"

            elif hasattr(content_type, 'document_message'):
                attrs.media_type = "document"

            elif hasattr(content_type, 'audio_message'):
                audio_msg = content_type.audio_message
                if hasattr(audio_msg, 'ptt') and audio_msg.ptt:
                    attrs.media_type = "ptt"
                else:
                    attrs.media_type = "audio"

            elif hasattr(content_type, 'video_message'):
                attrs.media_type = "video"

            elif hasattr(content_type, 'location_message'):
                attrs.media_type = "location"

            elif hasattr(content_type, 'live_location_message'):
                attrs.media_type = "location"

            elif hasattr(content_type, 'contact_message'):
                attrs.media_type = "vcard"

            elif hasattr(content_type, 'contacts_array_message'):
                attrs.media_type = "contact_array"

            elif hasattr(content_type, 'poll_creation_message'):
                attrs.poll_type = "creation"
                attrs.type = "poll"

            elif hasattr(content_type, 'poll_update_message'):
                attrs.poll_type = "vote"
                attrs.type = "poll"
                attrs.decrypt_fail = "hide"  # events.DecryptFailHide

            elif hasattr(content_type, 'reaction_message'):
                attrs.type = "reaction"
                attrs.decrypt_fail = "hide"

            elif hasattr(content_type, 'edit_message'):
                attrs.edit = "message_edit"  # types.EditAttributeMessageEdit
                attrs.decrypt_fail = "hide"

        # Set type to "media" if media_type is set but type isn't
        if attrs.media_type and not attrs.type:
            attrs.type = "media"

    elif hasattr(payload, 'application_data') and payload.application_data:
        app_data = payload.application_data
        if hasattr(app_data, 'application_content'):
            app_content = app_data.application_content
            if hasattr(app_content, 'revoke'):
                revoke = app_content.revoke
                if hasattr(revoke, 'key') and revoke.key and revoke.key.from_me:
                    attrs.edit = "sender_revoke"  # types.EditAttributeSenderRevoke
                else:
                    attrs.edit = "admin_revoke"  # types.EditAttributeAdminRevoke
                attrs.decrypt_fail = "hide"

    # Default fallback - matches Go function end
    if not attrs.type:
        attrs.type = "text"

    return attrs


def prepare_message_node_v3(
    client: 'Client',
    to: 'JID',
    own_id: 'JID',
    message_id: 'MessageID',
    payload: Optional['MessageTransport.Payload'],
    skdm: Optional['MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage'],
    msg_attrs: MessageAttrs,
    franking_tag: bytes,
    participants: List['JID'],
    timings: 'MessageDebugTimings'
) -> Tuple['BinaryNode', List['JID'], Optional[Exception]]:
    """Prepare a message node for v3 protocol - matches Go Client.prepareMessageNodeV3 method."""
    start = time.time()
    all_devices = user.get_user_devices_context(client, participants)
    timings.get_devices = time.time() - start

    # Build attributes - matches Go implementation exactly
    enc_attrs = {}
    attrs = {
        "id": str(message_id),
        "type": msg_attrs.type,
        "to": str(to)
    }

    # Only include mediatype on DMs, for groups it's in the skmsg node
    if payload and msg_attrs.media_type:
        enc_attrs["mediatype"] = msg_attrs.media_type

    if msg_attrs.edit:
        attrs["edit"] = str(msg_attrs.edit)

    if msg_attrs.decrypt_fail:
        enc_attrs["decrypt-fail"] = str(msg_attrs.decrypt_fail)

    # Create DSM - matches Go structure
    dsm = MessageTransport.Protocol.Integral.DeviceSentMessage(
        destinationJID=str(to),
        phash=""
    )

    start = time.time()
    participant_nodes = encrypt_message_for_devices_v3(
        all_devices, own_id, message_id, payload, skdm, dsm, enc_attrs
    )
    timings.peer_encrypt = time.time() - start

    # Build content - matches Go node building
    content = [
        create_binary_node(
            tag="participants",
            content=participant_nodes
        )
    ]

    # Meta attributes - matches Go logic
    meta_attrs = {}
    if msg_attrs.poll_type:
        meta_attrs["polltype"] = msg_attrs.poll_type
    if msg_attrs.decrypt_fail:
        meta_attrs["decrypt-fail"] = str(msg_attrs.decrypt_fail)

    if meta_attrs:
        content.append(create_binary_node(
            tag="meta",
            attrs=meta_attrs
        ))

    # Add trace request ID - matches Go uuid generation
    trace_request_id = str(uuid.uuid4())
    # Additional content nodes would be added here matching Go implementation

    node = create_binary_node(
        tag="message",
        attrs=attrs,
        content=content
    )

    return node, all_devices, None

def encrypt_message_for_devices_v3():
    raise NotImplementedError

def encrypt_message_for_device_and_wrap_v3():
    raise NotImplementedError

def encrypt_message_for_device_v3():
    raise NotImplementedError
