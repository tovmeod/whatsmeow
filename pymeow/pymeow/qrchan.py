"""
QR code channel for WhatsApp Web client pairing.

Port of whatsmeow/qrchan.go
"""
import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional, List, Callable, Any, Dict, cast
import threading
from enum import Enum

from .types.events.events import (
    QR, PairSuccess, PairError, QRScannedWithoutMultidevice,
    Connected, ConnectFailure, LoggedOut, TemporaryBan, Disconnected, ClientOutdated
)
from .exceptions import ClientIsNilError, QRAlreadyConnectedError, QRStoreContainsIDError


@dataclass
class QRChannelItem:
    """
    Represents an item sent through the QR channel.

    Attributes:
        event: The type of event, "code" for new QR codes (see code field) and "error" for pairing errors (see error field).
               For non-code/error events, you can compare the whole item to the event variables (like QRChannelSuccess).
        error: If the item is a pair error, then this field contains the error message.
        code: If the item is a new code, then this field contains the raw data.
        timeout: The timeout after which the next code will be sent down the channel.
    """
    event: str
    error: Optional[Exception] = None
    code: str = ""
    timeout: float = 0.0


# Event type constants
QR_CHANNEL_EVENT_CODE = "code"
QR_CHANNEL_EVENT_ERROR = "error"

# Possible final items in the QR channel
QR_CHANNEL_SUCCESS = QRChannelItem(event="success")
QR_CHANNEL_TIMEOUT = QRChannelItem(event="timeout")
QR_CHANNEL_ERR_UNEXPECTED_EVENT = QRChannelItem(event="err-unexpected-state")
QR_CHANNEL_CLIENT_OUTDATED = QRChannelItem(event="err-client-outdated")
QR_CHANNEL_SCANNED_WITHOUT_MULTIDEVICE = QRChannelItem(event="err-scanned-without-multidevice")


class QRChannel:
    """Internal implementation of the QR channel."""

    def __init__(self, client, output_channel, logger):
        """
        Initialize a QR channel.

        Args:
            client: The WhatsApp client instance
            output_channel: The channel to send QR codes and events to
            logger: Logger instance
        """
        self.client = client
        self.lock = threading.RLock()
        self.logger = logger
        self.handler_id = None
        self.closed = False
        self.output = output_channel
        self.stop_qrs = threading.Event()

    def emit_qrs(self, codes: List[str]):
        """
        Emit QR codes with appropriate timeouts.

        Args:
            codes: List of QR codes to emit
        """
        next_code = None
        while True:
            if not codes:
                with self.lock:
                    if not self.closed:
                        self.logger.debug("Ran out of QR codes, closing channel with status %s and disconnecting client", QR_CHANNEL_TIMEOUT)
                        try:
                            self.output.put_nowait(QR_CHANNEL_TIMEOUT)
                        except asyncio.QueueFull:
                            pass
                        self.output.close()
                        self.closed = True
                        self.client.remove_event_handler(self.handler_id)
                        self.client.disconnect()
                    else:
                        self.logger.debug("Ran out of QR codes, but channel is already closed")
                return
            elif self.closed:
                self.logger.debug("QR code channel is closed, exiting QR emitter")
                return

            timeout = 20.0  # Default timeout in seconds
            if len(codes) == 6:
                timeout = 60.0

            next_code, codes = codes[0], codes[1:]
            self.logger.debug("Emitting QR code %s", next_code)

            try:
                self.output.put_nowait(QRChannelItem(
                    code=next_code,
                    timeout=timeout,
                    event=QR_CHANNEL_EVENT_CODE
                ))
            except asyncio.QueueFull:
                self.logger.debug("Output channel didn't accept code, exiting QR emitter")
                with self.lock:
                    if not self.closed:
                        self.output.close()
                        self.closed = True
                        self.client.remove_event_handler(self.handler_id)
                        self.client.disconnect()
                return

            # Wait for timeout or stop signal
            stop_time = time.time() + timeout
            while time.time() < stop_time:
                if self.stop_qrs.wait(0.1):
                    self.logger.debug("Got signal to stop QR emitter")
                    return
                if self.closed:
                    self.logger.debug("Channel is closed, stopping QR emitter")
                    return

    def handle_event(self, raw_evt: Any):
        """
        Handle events from the client and update the QR channel accordingly.

        Args:
            raw_evt: The event received from the client
        """
        with self.lock:
            if self.closed:
                self.logger.debug("Dropping event of type %s, channel is closed", type(raw_evt).__name__)
                return

            output_type = None

            if isinstance(raw_evt, QR):
                self.logger.debug("Received QR code event, starting to emit codes to channel")
                threading.Thread(target=self.emit_qrs, args=(raw_evt.codes.copy(),), daemon=True).start()
                return
            elif isinstance(raw_evt, QRScannedWithoutMultidevice):
                self.logger.debug("QR code scanned without multidevice enabled")
                try:
                    self.output.put_nowait(QR_CHANNEL_SCANNED_WITHOUT_MULTIDEVICE)
                except asyncio.QueueFull:
                    pass
                return
            elif isinstance(raw_evt, ClientOutdated):
                output_type = QR_CHANNEL_CLIENT_OUTDATED
            elif isinstance(raw_evt, PairSuccess):
                output_type = QR_CHANNEL_SUCCESS
            elif isinstance(raw_evt, PairError):
                output_type = QRChannelItem(
                    event=QR_CHANNEL_EVENT_ERROR,
                    error=raw_evt.error
                )
            elif isinstance(raw_evt, Disconnected):
                output_type = QR_CHANNEL_TIMEOUT
            elif isinstance(raw_evt, (Connected, ConnectFailure, LoggedOut, TemporaryBan)):
                output_type = QR_CHANNEL_ERR_UNEXPECTED_EVENT
            else:
                return

            self.stop_qrs.set()

            if not self.closed:
                self.logger.debug("Closing channel with status %s", output_type)
                try:
                    self.output.put_nowait(output_type)
                except asyncio.QueueFull:
                    pass
                self.output.close()
                self.closed = True
            else:
                self.logger.debug("Got status %s, but channel is already closed", output_type)

            # Has to be done in background to avoid deadlock with event handlers lock
            threading.Thread(target=self.client.remove_event_handler, args=(self.handler_id,), daemon=True).start()


def get_qr_channel(client, max_size=8):
    """
    Returns a channel that automatically outputs a new QR code when the previous one expires.

    This must be called *before* connect(). It will then listen to all the relevant events from the client.

    The last value to be emitted will be a special event like "success", "timeout" or another error code
    depending on the result of the pairing. The channel will be closed immediately after one of those.

    Args:
        client: The WhatsApp client instance
        max_size: Maximum size of the channel buffer

    Returns:
        A tuple containing the channel to receive QR codes and events from, and any error that occurred

    Raises:
        ClientIsNilError: If the client is None
        QRAlreadyConnectedError: If the client is already connected
        QRStoreContainsIDError: If the client store already contains an ID
    """
    if client is None:
        raise ClientIsNilError("Client is nil")
    if client.is_connected():
        raise QRAlreadyConnectedError("Client is already connected")
    if client.store.id is not None:
        raise QRStoreContainsIDError("Store already contains ID")

    output = asyncio.Queue(maxsize=max_size)
    qrc = QRChannel(
        client=client,
        output_channel=output,
        logger=logging.getLogger("QRChannel")
    )
    qrc.handler_id = client.add_event_handler(qrc.handle_event)

    return output
