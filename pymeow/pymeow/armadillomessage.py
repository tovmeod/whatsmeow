"""
Armadillo message handling functionality.

Port of whatsmeow/armadillomessage.go
"""
import asyncio
import contextlib
from typing import Optional, Tuple

import google.protobuf.proto_pb2 as proto

from .types.events import FBMessage
from .types.message import MessageInfo
from .generated.waMsgTransport import WAMsgTransport_pb2 as waMsgTransport
from .generated.waMsgApplication import WAMsgApplication_pb2 as waMsgApplication
from .generated.waCommon import WACommon_pb2 as waCommon
from .generated.waArmadilloApplication import WAArm_pb2 as armadillo


async def decode_armadillo(data: bytes) -> Tuple[FBMessage, Optional[Exception]]:
    """
    Decode an armadillo message from binary data.

    Args:
        data: The binary data to decode

    Returns:
        A tuple containing the decoded FBMessage and an optional error
    """
    dec = FBMessage()

    # Unmarshal the transport layer
    transport = waMsgTransport.MessageTransport()
    try:
        transport.ParseFromString(data)
    except Exception as err:
        return dec, Exception(f"failed to unmarshal transport: {err}")

    dec.transport = transport

    # Check if there's a payload
    if not transport.HasField("payload"):
        return dec, None

    # Decode the application layer
    try:
        application = transport.payload.Decode()
    except Exception as err:
        return dec, Exception(f"failed to unmarshal application: {err}")

    dec.application = application

    # Check if there's a payload in the application
    if not application.HasField("payload"):
        return dec, None

    # Handle different content types
    content = application.payload.content

    if application.payload.HasField("coreContent"):
        err = Exception("unsupported core content payload")
    elif application.payload.HasField("signal"):
        err = Exception("unsupported signal payload")
    elif application.payload.HasField("applicationData"):
        err = Exception("unsupported application data payload")
    elif application.payload.HasField("subProtocol"):
        sub_protocol = application.payload.subProtocol.subProtocol

        if sub_protocol.HasField("consumerMessage"):
            try:
                dec.message = sub_protocol.consumerMessage.Decode()
            except Exception as err:
                return dec, err
        elif sub_protocol.HasField("businessMessage"):
            dec.message = armadillo.Unsupported_BusinessApplication(sub_protocol.businessMessage)
        elif sub_protocol.HasField("paymentMessage"):
            dec.message = armadillo.Unsupported_PaymentApplication(sub_protocol.paymentMessage)
        elif sub_protocol.HasField("multiDevice"):
            try:
                dec.message = sub_protocol.multiDevice.Decode()
            except Exception as err:
                return dec, err
        elif sub_protocol.HasField("voip"):
            dec.message = armadillo.Unsupported_Voip(sub_protocol.voip)
        elif sub_protocol.HasField("armadillo"):
            try:
                dec.message = sub_protocol.armadillo.Decode()
            except Exception as err:
                return dec, err
        else:
            return dec, Exception(f"unsupported subprotocol type: {type(sub_protocol)}")
    else:
        err = Exception(f"unsupported application payload content type: {type(content)}")

    return dec, err


async def handle_decrypted_armadillo(cli, ctx, info: MessageInfo, decrypted: bytes, retry_count: int) -> bool:
    """
    Handle a decrypted armadillo message.

    Args:
        cli: The client instance
        ctx: The context
        info: Information about the message
        decrypted: The decrypted message data
        retry_count: The number of retries

    Returns:
        True if the message was handled successfully, False otherwise
    """
    dec, err = await decode_armadillo(decrypted)
    if err:
        cli.log.warning(f"Failed to decode armadillo message from {info.source_string()}: {err}")
        return False

    dec.info = info
    dec.retry_count = retry_count

    # Handle sender key distribution message
    if (dec.transport.HasField("protocol") and
        dec.transport.protocol.HasField("ancillary") and
        dec.transport.protocol.ancillary.HasField("skdm")):

        if not info.is_group:
            cli.log.warning(f"Got sender key distribution message in non-group chat from {info.sender}")
        else:
            skdm = dec.transport.protocol.ancillary.skdm
            await cli.handle_sender_key_distribution_message(ctx, info.chat, info.sender, skdm.axolotlSenderKeyDistributionMessage)

    # Dispatch event if there's a message
    if dec.message:
        cli.dispatch_event(dec)

    return True
