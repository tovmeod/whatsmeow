"""
Media retry handling for WhatsApp.

Port of whatsmeow/mediaretry.go
"""
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from Crypto.Random import get_random_bytes

from .binary.node import Attrs, Node
from .exceptions import (
    ElementMissingError,
    ErrClientIsNil,
    ErrMediaNotAvailableOnPhone,
    ErrNotLoggedIn,
    ErrUnknownMediaRetryError,
)
from .generated.waMmsRetry import WAMmsRetry_pb2
from .types import events
from .types.message import MessageID, MessageInfo
from .util import gcmutil, hkdfutil

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)


def get_media_retry_key(media_key: bytes) -> bytes:
    """Generate the cipher key for media retry encryption.

    Args:
        media_key: The original media key

    Returns:
        The cipher key for encryption/decryption
    """
    return hkdfutil.sha256(media_key, b"", b"WhatsApp Media Retry Notification", 32)


def encrypt_media_retry_receipt(message_id: MessageID, media_key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt a media retry receipt.

    Args:
        message_id: The message ID to create receipt for
        media_key: The media key for encryption

    Returns:
        Tuple of (ciphertext, iv)

    Raises:
        Exception: If marshaling or encryption fails
    """
    receipt = WAMmsRetry_pb2.ServerErrorReceipt()
    receipt.stanzaID = str(message_id)

    try:
        plaintext = receipt.SerializeToString()
    except Exception as e:
        raise Exception(f"failed to marshal payload: {e}")

    iv = get_random_bytes(12)
    ciphertext = gcmutil.encrypt(get_media_retry_key(media_key), iv, plaintext, str(message_id).encode())

    return ciphertext, iv


async def send_media_retry_receipt(client: "Client", message: MessageInfo, media_key: bytes) -> None:
    """Send a request to the phone to re-upload the media in a message.

    This is mostly relevant when handling history syncs and getting a 404 or 410 error downloading media.
    Rough example on how to use it (will not work out of the box, you must adjust it depending on what you need exactly):

        media_retry_cache = {}  # type: Dict[MessageID, Any]

        evt = await client.parse_web_message(chat_jid, history_msg.message)
        image_msg = evt.message.image_message  # replace this with the part of the message you want to download
        try:
            data = await client.download(image_msg)
        except (ErrMediaDownloadFailedWith404, ErrMediaDownloadFailedWith410):
            await send_media_retry_receipt(client, evt.info, image_msg.media_key)
            # You need to store the event data somewhere as it's necessary for handling the retry response.
            media_retry_cache[evt.info.id] = image_msg

    The response will come as an events.MediaRetry. The response will then have to be decrypted
    using decrypt_media_retry_notification and the same media key passed here. If the media retry was successful,
    the decrypted notification should contain an updated direct_path, which can be used to download the file.

        async def event_handler(raw_evt):
            if isinstance(raw_evt, events.MediaRetry):
                image_msg = media_retry_cache[raw_evt.message_id]
                retry_data = decrypt_media_retry_notification(raw_evt, image_msg.media_key)
                if retry_data is None or retry_data.result != waMmsRetry_pb2.MediaRetryNotification.SUCCESS:
                    return
                # Use the new path to download the attachment
                image_msg.direct_path = retry_data.direct_path
                data = await client.download(image_msg)
                # Alternatively, you can use client.download_media_with_path and provide the individual fields manually.

    Args:
        client: The client instance
        message: The message info for the media to retry
        media_key: The media key for encryption

    Raises:
        ErrClientIsNil: If client is None
        ErrNotLoggedIn: If client is not logged in
        Exception: If encryption or sending fails
    """
    if client is None:
        raise ErrClientIsNil()

    try:
        ciphertext, iv = encrypt_media_retry_receipt(message.id, media_key)
    except Exception as e:
        raise Exception(f"failed to prepare encrypted retry receipt: {e}")

    own_id = client.get_own_id().to_non_ad()
    if own_id.is_empty():
        raise ErrNotLoggedIn()

    rmr_attrs = Attrs({
        "jid": str(message.chat),
        "from_me": str(message.message_source.is_from_me).lower(),
    })
    if message.message_source.is_group:
        rmr_attrs["participant"] = str(message.sender)

    encrypted_request = [
        Node(tag="enc_p", content=ciphertext),
        Node(tag="enc_iv", content=iv),
    ]

    await client.send_node(Node(
        tag="receipt",
        attrs=Attrs({
            "id": str(message.id),
            "to": str(own_id),
            "type": "server-error",
        }),
        content=[
            Node(tag="encrypt", content=encrypted_request),
            Node(tag="rmr", attrs=rmr_attrs),
        ]
    ))


def decrypt_media_retry_notification(evt: events.MediaRetry, media_key: bytes) -> Optional[WAMmsRetry_pb2.MediaRetryNotification]:
    """Decrypt a media retry notification using the media key.

    See send_media_retry_receipt for more info on how to use this.

    Args:
        evt: The media retry event
        media_key: The media key used for decryption

    Returns:
        The decrypted notification, or None if decryption failed

    Raises:
        ErrMediaNotAvailableOnPhone: If error code is 2
        ErrUnknownMediaRetryError: If unknown error code
        Exception: If decryption or unmarshaling fails
    """
    if evt.error is not None and evt.ciphertext is None:
        if evt.error.code == 2:
            raise ErrMediaNotAvailableOnPhone()
        raise ErrUnknownMediaRetryError(f"unknown media retry error (code: {evt.error.code})")

    try:
        plaintext = gcmutil.decrypt(
            get_media_retry_key(media_key),
            evt.iv,
            evt.ciphertext,
            str(evt.message_id).encode()
        )
    except Exception as e:
        raise Exception(f"failed to decrypt notification: {e}")

    try:
        notif = WAMmsRetry_pb2.MediaRetryNotification()
        notif.ParseFromString(plaintext)
        return notif
    except Exception as e:
        raise Exception(f"failed to unmarshal notification (invalid encryption key?): {e}")


def parse_media_retry_notification(node: Node) -> events.MediaRetry:
    """Parse a media retry notification from a binary node.

    Args:
        node: The binary node containing the notification

    Returns:
        The parsed media retry event

    Raises:
        ElementMissingError: If required elements are missing
        Exception: If parsing fails
    """
    ag = node.attr_getter()

    evt = events.MediaRetry()
    evt.timestamp = ag.unix_time("t")
    evt.message_id = MessageID(ag.string("id"))

    if not ag.ok():
        raise Exception(f"failed to parse attributes: {ag.error()}")

    rmr, found = node.get_optional_child_by_tag("rmr")
    if not rmr:
        raise ElementMissingError(tag="rmr", in_location="retry notification")

    rmr_ag = rmr.attr_getter()
    evt.chat_id = rmr_ag.jid("jid")
    evt.from_me = rmr_ag.bool("from_me")
    evt.sender_id = rmr_ag.optional_jid_or_empty("participant")

    if not rmr_ag.ok():
        raise Exception(f"missing attributes in <rmr> tag: {rmr_ag.error()}")

    error_node, found = node.get_optional_child_by_tag("error")
    if error_node:
        evt.error = events.MediaRetryError(
            code=error_node.attr_getter().int("code")
        )
        return evt

    enc_p = node.get_child_by_tag("encrypt", "enc_p")
    if not isinstance(enc_p.content, bytes):
        raise ElementMissingError(tag="enc_p", in_location=f"retry notification {evt.message_id}")
    evt.ciphertext = enc_p.content

    enc_iv = node.get_child_by_tag("encrypt", "enc_iv")
    if not isinstance(enc_iv.content, bytes):
        raise ElementMissingError(tag="enc_iv", in_location=f"retry notification {evt.message_id}")
    evt.iv = enc_iv.content

    return evt


async def handle_media_retry_notification(client: "Client", node: Node) -> None:
    """Handle a media retry notification.

    Args:
        client: The client instance
        node: The binary node containing the notification
    """
    try:
        evt = parse_media_retry_notification(node)
        await client.dispatch_event(evt)
    except Exception as e:
        logger.warning(f"Failed to parse media retry notification: {e}")
