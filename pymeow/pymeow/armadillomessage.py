"""
Armadillo message handling functionality.

Port of whatsmeow/armadillomessage.go
"""
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from . import message
from .datatypes.message import MessageID
from .generated.waArmadilloApplication import WAArmadilloApplication_pb2
from .generated.waConsumerApplication import WAConsumerApplication_pb2
from .generated.waMsgApplication import WAMsgApplication_pb2
from .generated.waMsgTransport import WAMsgTransport_pb2
from .generated.waMultiDevice import WAMultiDevice_pb2

if TYPE_CHECKING:
    from .client import Client
    from .datatypes import MessageInfo
    from .datatypes.events import FBMessage

logger = logging.getLogger(__name__)

async def handle_decrypted_armadillo(
    client: 'Client',
    info: 'MessageInfo',
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
    dec, err = decode_armadillo(decrypted)
    if err is not None:
        logger.warning(f"Failed to decode armadillo message from {info.source_string()}: {err}")
        return False

    # Go: dec.Info = *info (value copy)
    dec.info = info
    dec.retry_count = retry_count

    # Handle sender key distribution message if present
    # Go: if dec.Transport.GetProtocol().GetAncillary().GetSkdm() != nil
    if (dec.transport and
        dec.transport.HasField("protocol") and
        dec.transport.protocol.HasField("ancillary") and
        dec.transport.protocol.ancillary.HasField("skdm")):

        # Go: if !info.IsGroup
        if not info.message_source.is_group:
            logger.warning(f"Got sender key distribution message in non-group chat from {info.sender}")
        else:
            skdm = dec.transport.protocol.ancillary.skdm
            await message.handle_sender_key_distribution_message(
                client,
                info.chat,
                info.sender,
                skdm.axolotlSenderKeyDistributionMessage
            )

    # Dispatch event if there's a message
    # Go: if dec.Message != nil { cli.dispatchEvent(&dec) }
    if dec.message is not None:
        await client.dispatch_event(dec)

    return True


def decode_armadillo(data: bytes) -> Tuple['FBMessage', Optional[Exception]]:
    """
    Port of Go method decodeArmadillo from armadillomessage.go.

    Decode an armadillo message from binary data.

    Args:
        data: The binary data to decode

    Returns:
        Tuple containing the decoded FBMessage and an optional error
    """
    from .datatypes import MessageInfo
    from .datatypes.events import FBMessage
    # Fixed: FBMessage requires info and message parameters
    # Use placeholder values that will be overwritten
    dec = FBMessage(
        info=MessageInfo(id=MessageID()),  # This will be overwritten with actual info
        message=None         # This will be set if we decode a message
    )

    # Unmarshal the transport layer
    # Go: err = proto.Unmarshal(data, &transport)
    try:
        transport = WAMsgTransport_pb2.MessageTransport()
        transport.ParseFromString(data)
    except Exception as e:
        return dec, Exception(f"failed to unmarshal transport: {e}")

    dec.transport = transport

    # Check if there's a payload
    # Go: if transport.GetPayload() == nil { return }
    if not transport.HasField("payload"):
        return dec, None

    # Decode the application layer
    # Go: application, err := transport.GetPayload().Decode()
    try:
        application = WAMsgApplication_pb2.MessageApplication()
        application.ParseFromString(transport.payload.applicationPayload.payload)
    except Exception as e:
        return dec, Exception(f"failed to unmarshal application: {e}")

    dec.application = application

    # Check if there's a payload in the application
    # Go: if application.GetPayload() == nil { return }
    if not application.HasField("payload"):
        return dec, None

    # Go uses switch statement with type assertions
    # Go: switch typedContent := application.GetPayload().GetContent().(type)
    payload = application.payload

    if payload.HasField("core_content"):
        # Go: case *waMsgApplication.MessageApplication_Payload_CoreContent:
        err = Exception("unsupported core content payload")
    elif payload.HasField("signal"):
        # Go: case *waMsgApplication.MessageApplication_Payload_Signal:
        err = Exception("unsupported signal payload")
    elif payload.HasField("application_data"):
        # Go: case *waMsgApplication.MessageApplication_Payload_ApplicationData:
        err = Exception("unsupported application data payload")
    elif payload.HasField("sub_protocol"):
        # Go: case *waMsgApplication.MessageApplication_Payload_SubProtocol:
        sub_protocol_payload = payload.subProtocol

        # Go: switch subProtocol := typedContent.SubProtocol.GetSubProtocol().(type)
        if sub_protocol_payload.HasField("consumer_message"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_ConsumerMessage:
            try:
                consumer_app = WAConsumerApplication_pb2.ConsumerApplication()
                consumer_app.ParseFromString(sub_protocol_payload.consumerMessage.payload)
                dec.message = consumer_app
            except Exception as e:
                return dec, e
        elif sub_protocol_payload.HasField("business_message"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_BusinessMessage:
            # Go: dec.Message = (*armadillo.Unsupported_BusinessApplication)(subProtocol.BusinessMessage)
            dec.message = sub_protocol_payload.businessMessage
        elif sub_protocol_payload.HasField("payment_message"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_PaymentMessage:
            # Go: dec.Message = (*armadillo.Unsupported_PaymentApplication)(subProtocol.PaymentMessage)
            dec.message = sub_protocol_payload.paymentMessage
        elif sub_protocol_payload.HasField("multi_device"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_MultiDevice:
            try:
                multi_device = WAMultiDevice_pb2.MultiDevice()
                multi_device.ParseFromString(sub_protocol_payload.multiDevice.payload)
                dec.message = multi_device
            except Exception as e:
                return dec, e
        elif sub_protocol_payload.HasField("voip"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_Voip:
            # Go: dec.Message = (*armadillo.Unsupported_Voip)(subProtocol.Voip)
            dec.message = sub_protocol_payload.voip
        elif sub_protocol_payload.HasField("armadillo"):
            # Go: case *waMsgApplication.MessageApplication_SubProtocolPayload_Armadillo:
            try:
                armadillo_app = WAArmadilloApplication_pb2.Armadillo()
                armadillo_app.ParseFromString(sub_protocol_payload.armadillo.payload)
                dec.message = armadillo_app
            except Exception as e:
                return dec, e
        else:
            # Go: default: return dec, fmt.Errorf("unsupported subprotocol type: %T", subProtocol)
            return dec, Exception(f"unsupported subprotocol type: {type(sub_protocol_payload)}")

        # The Go code has additional logic with protoMsg and subData that's not used in the current flow
        err = None
    else:
        # Go: default: err = fmt.Errorf("unsupported application payload content type: %T", typedContent)
        err = Exception(f"unsupported application payload content type: {type(payload)}")

    return dec, err
