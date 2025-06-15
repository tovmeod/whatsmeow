"""
Armadillo message handling functionality.

Port of whatsmeow/armadillomessage.go
"""
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from . import message
from .generated.waArmadilloApplication import WAArmadilloApplication_pb2 as armadillo_pb2
from .generated.waCommon import WACommon_pb2 as wa_common_pb2
from .generated.waMsgApplication import WAMsgApplication_pb2 as wa_msg_application_pb2
from .generated.waMsgTransport import WAMsgTransport_pb2 as wa_msg_transport_pb2
from .types import MessageInfo
from .types.events import FBMessage

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)

async def handle_decrypted_armadillo(
    client: 'Client',
    info: MessageInfo,
    decrypted: bytes,
    retry_count: int
) -> bool:
    """
    Port of Go method handleDecryptedArmadillo from armadillomessage.go.

    Handle a decrypted armadillo message by decoding it and dispatching events.

    Args:
        client: The WhatsApp client instance
        info: Message information
        decrypted: The decrypted message data
        retry_count: The number of retries for this message

    Returns:
        True if the message was handled successfully, False otherwise
    """
    # TODO: Review decodeArmadillo implementation
    # TODO: Review handleSenderKeyDistributionMessage implementation
    # TODO: Review dispatchEvent implementation

    dec, err = decode_armadillo(decrypted)
    if err is not None:
        logger.warning(f"Failed to decode armadillo message from {info.source_string()}: {err}")
        return False

    dec.info = info
    dec.retry_count = retry_count

    # Handle sender key distribution message if present
    if (dec.transport and
        dec.transport.HasField("protocol") and
        dec.transport.protocol.HasField("ancillary") and
        dec.transport.protocol.ancillary.HasField("skdm")):

        if not info.message_source.is_group:
            logger.warning(f"Got sender key distribution message in non-group chat from {info.sender}")
        else:
            skdm = dec.transport.protocol.ancillary.skdm
            await message.handle_sender_key_distribution_message(
                client,
                info.chat,
                info.sender,
                skdm.axolotl_sender_key_distribution_message
            )

    # Dispatch event if there's a message
    if dec.message is not None:
        await client.dispatch_event(dec)

    return True


def decode_armadillo(data: bytes) -> Tuple[FBMessage, Optional[Exception]]:
    """
    Port of Go method decodeArmadillo from armadillomessage.go.

    Decode an armadillo message from binary data.

    Args:
        data: The binary data to decode

    Returns:
        Tuple containing the decoded FBMessage and an optional error
    """
    # TODO: Review FBMessage implementation
    # TODO: Review protobuf message implementations

    dec = FBMessage()

    # Unmarshal the transport layer
    try:
        transport = wa_msg_transport_pb2.MessageTransport()
        transport.ParseFromString(data)
    except Exception as e:
        return dec, Exception(f"failed to unmarshal transport: {e}")

    dec.transport = transport

    # Check if there's a payload
    if not transport.HasField("payload"):
        return dec, None

    # Decode the application layer
    try:
        application = transport.payload.Decode()
    except Exception as e:
        return dec, Exception(f"failed to unmarshal application: {e}")

    dec.application = application

    # Check if there's a payload in the application
    if not application.HasField("payload"):
        return dec, None

    # Handle different content types based on the payload content
    payload = application.payload

    if payload.HasField("core_content"):
        err = Exception("unsupported core content payload")
    elif payload.HasField("signal"):
        err = Exception("unsupported signal payload")
    elif payload.HasField("application_data"):
        err = Exception("unsupported application data payload")
    elif payload.HasField("sub_protocol"):
        # Handle subprotocol messages
        sub_protocol_payload = payload.sub_protocol
        sub_protocol = sub_protocol_payload.sub_protocol

        if sub_protocol.HasField("consumer_message"):
            try:
                dec.message = sub_protocol.consumer_message.Decode()
            except Exception as e:
                return dec, e
        elif sub_protocol.HasField("business_message"):
            # Create unsupported business application wrapper
            dec.message = armadillo_pb2.Unsupported_BusinessApplication()
            dec.message.CopyFrom(sub_protocol.business_message)
        elif sub_protocol.HasField("payment_message"):
            # Create unsupported payment application wrapper
            dec.message = armadillo_pb2.Unsupported_PaymentApplication()
            dec.message.CopyFrom(sub_protocol.payment_message)
        elif sub_protocol.HasField("multi_device"):
            try:
                dec.message = sub_protocol.multi_device.Decode()
            except Exception as e:
                return dec, e
        elif sub_protocol.HasField("voip"):
            # Create unsupported voip wrapper
            dec.message = armadillo_pb2.Unsupported_Voip()
            dec.message.CopyFrom(sub_protocol.voip)
        elif sub_protocol.HasField("armadillo"):
            try:
                dec.message = sub_protocol.armadillo.Decode()
            except Exception as e:
                return dec, e
        else:
            return dec, Exception(f"unsupported subprotocol type: {type(sub_protocol)}")

        err = None
    else:
        err = Exception(f"unsupported application payload content type: {type(payload.content)}")

    return dec, err
