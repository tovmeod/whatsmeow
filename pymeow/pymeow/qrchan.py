"""
QR code channel for WhatsApp Web client pairing.

This module provides an asynchronous implementation of the QR code channel
for WhatsApp Web client pairing. It handles the QR code generation, display,
and pairing process.

Usage example:
    ```python
    import asyncio
    from pymeow import Client
    from pymeow.qrchan import get_qr_channel

    async def main():
        # Create a client
        client = Client(...)

        # Get a QR channel
        qr_channel = await get_qr_channel(client)

        # Connect the client
        await client.connect()

        # Process QR codes
        async with qr_channel as channel:
            async for item in channel:
                if item.event == "code":
                    print(f"Scan this QR code: {item.code}")
                elif item.event == "success":
                    print("Successfully paired!")
                    break
                elif item.event.startswith("err"):
                    print(f"Error: {item.event}")
                    if item.error:
                        print(f"Error details: {item.error}")
                    break

    asyncio.run(main())
    ```

Port of whatsmeow/qrchan.go
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from .client import Client
from .exceptions import ErrClientIsNil, ErrQRAlreadyConnected, ErrQRStoreContainsID
from .datatypes.events.events import (
    QR,
    ClientOutdated,
    Connected,
    ConnectFailure,
    Disconnected,
    LoggedOut,
    PairError,
    PairSuccess,
    QRScannedWithoutMultidevice,
    TemporaryBan,
)


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

    def __str__(self) -> str:
        """Return a string representation of the QRChannelItem."""
        if self.event == QR_CHANNEL_EVENT_CODE:
            return f"QRChannelItem(event={self.event}, code={self.code}, timeout={self.timeout})"
        elif self.event == QR_CHANNEL_EVENT_ERROR:
            return f"QRChannelItem(event={self.event}, error={self.error})"
        else:
            return f"QRChannelItem(event={self.event})"


# Event type constants
QR_CHANNEL_EVENT_CODE = "code"
QR_CHANNEL_EVENT_ERROR = "error"
QR_CHANNEL_EVENT_SUCCESS = "success"
QR_CHANNEL_EVENT_TIMEOUT = "timeout"
QR_CHANNEL_EVENT_UNEXPECTED = "err-unexpected-state"
QR_CHANNEL_EVENT_OUTDATED = "err-client-outdated"
QR_CHANNEL_EVENT_NO_MULTIDEVICE = "err-scanned-without-multidevice"

# Possible final items in the QR channel
QR_CHANNEL_SUCCESS = QRChannelItem(event=QR_CHANNEL_EVENT_SUCCESS)
QR_CHANNEL_TIMEOUT = QRChannelItem(event=QR_CHANNEL_EVENT_TIMEOUT)
QR_CHANNEL_ERR_UNEXPECTED_EVENT = QRChannelItem(event=QR_CHANNEL_EVENT_UNEXPECTED)
QR_CHANNEL_CLIENT_OUTDATED = QRChannelItem(event=QR_CHANNEL_EVENT_OUTDATED)
QR_CHANNEL_SCANNED_WITHOUT_MULTIDEVICE = QRChannelItem(event=QR_CHANNEL_EVENT_NO_MULTIDEVICE)

logger = logging.getLogger(__name__)

class QRChannel:
    """
    Internal implementation of the QR channel.

    This class handles the QR code generation, display, and pairing process.
    It uses asyncio for asynchronous operation.
    """

    def __init__(self, client: Client, output_channel: asyncio.Queue[QRChannelItem]):
        """
        Initialize a QR channel.

        Args:
            client: The WhatsApp client instance
            output_channel: The asyncio Queue to send QR codes and events to
        """
        self.client = client
        self.closed = False
        self.output = output_channel
        self.stop_qrs = asyncio.Event()
        self._emit_task: Optional[asyncio.Task[None]]= None

    async def ainit(self) -> 'QRChannel':
        self.client.add_event_handler(self.handle_event)
        return self

    async def __aenter__(self) -> 'QRChannel':
        """
        Async context manager entry.

        Returns:
            The QRChannel instance for async iteration
        """
        return self

    def __aiter__(self) -> 'QRChannel':
        """
        Return self as an async iterator.

        Returns:
            The QRChannel instance
        """
        return self

    async def __anext__(self) -> QRChannelItem:
        """
        Get the next item from the queue.

        Returns:
            The next QRChannelItem from the queue

        Raises:
            StopAsyncIteration: When the queue is closed
        """
        try:
            # Wait for the next item with a timeout to allow for cancellation
            item = await asyncio.wait_for(self.output.get(), timeout=60.0)
            return item
        except asyncio.CancelledError:
            # Propagate cancellation
            raise
        except asyncio.TimeoutError:
            # Check if the channel is closed
            if self.closed:
                raise StopAsyncIteration
            # Otherwise, try again
            return await self.__anext__()
        except Exception as e:
            logger.error("Error getting next item from queue: %s", e)
            if self.closed:
                raise StopAsyncIteration
            raise

    async def __aexit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[Any]) -> None:
        """
        Async context manager exit.

        Ensures proper cleanup of resources.
        """
        if not self.closed:
            logger.debug("Closing QR channel due to context exit")
            await self.close()

    async def close(self) -> None:
        """
        Close the QR channel and clean up resources.
        """
        if not self.closed:
            logger.debug("Closing QR channel")
            self.stop_qrs.set()
            self.client.remove_event_handler(self.handle_event)
            self.closed = True

    async def emit_qrs(self, codes: List[str]) -> None:
        """
        Emit QR codes with appropriate timeouts.

        Args:
            codes: List of QR codes to emit
        """
        try:
            while True:
                if not codes:
                    if not self.closed:
                        logger.debug("Ran out of QR codes, closing channel with status %s and disconnecting client", QR_CHANNEL_TIMEOUT)
                        try:
                            await asyncio.wait_for(
                                self.output.put(QR_CHANNEL_TIMEOUT),
                                timeout=1.0
                            )
                        except asyncio.TimeoutError:
                            logger.warning("Timed out putting timeout event in queue")
                        except Exception as e:
                            logger.error("Error putting timeout event in queue: %s", e)

                        await self.close()
                        await self.client.disconnect()
                    else:
                        logger.debug("Ran out of QR codes, but channel is already closed")
                    return
                elif self.closed:
                    logger.debug("QR code channel is closed, exiting QR emitter")
                    return

                timeout = 20.0  # Default timeout in seconds
                if len(codes) == 6:
                    timeout = 60.0

                next_code, codes = codes[0], codes[1:]
                logger.debug("Emitting QR code %s", next_code)

                try:
                    await asyncio.wait_for(
                        self.output.put(QRChannelItem(
                            code=next_code,
                            timeout=timeout,
                            event=QR_CHANNEL_EVENT_CODE
                        )),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Timed out putting QR code in queue")
                    if not self.closed:
                        await self.close()
                        await self.client.disconnect()
                    return
                except Exception as e:
                    logger.error("Error putting QR code in queue: %s", e)
                    if not self.closed:
                        await self.close()
                        await self.client.disconnect()
                    return

                # Wait for timeout or stop signal
                try:
                    await asyncio.wait_for(self.stop_qrs.wait(), timeout=timeout)
                    logger.debug("Got signal to stop QR emitter")
                    return
                except asyncio.TimeoutError:
                    # Timeout expired, continue to next code
                    pass

                if self.closed:
                    logger.debug("Channel is closed, stopping QR emitter")
                    return
        except Exception as e:
            logger.error("Unexpected error in emit_qrs: %s", e, exc_info=True)
            if not self.closed:
                await self.close()
                await self.client.disconnect()

    async def handle_event(self, raw_evt: Any) -> None:
        """
        Handle events from the client and update the QR channel accordingly.

        Args:
            raw_evt: The event received from the client
        """
        logger.debug(f"QRChannel received event: {type(raw_evt).__name__}")
        try:
            if self.closed:
                logger.debug("Dropping event of type %s, channel is closed", type(raw_evt).__name__)
                return

            if isinstance(raw_evt, Disconnected):
                logger.info("QRChannel: Received Disconnected event during playback.")

            if isinstance(raw_evt, QR):
                logger.debug("Received QR code event, starting to emit codes to channel")
                # Create a task to emit QR codes asynchronously
                self._emit_task = asyncio.create_task(self.emit_qrs(raw_evt.codes.copy()))
                return
            elif isinstance(raw_evt, QRScannedWithoutMultidevice):
                logger.debug("QR code scanned without multidevice enabled")
                try:
                    await asyncio.wait_for(
                        self.output.put(QR_CHANNEL_SCANNED_WITHOUT_MULTIDEVICE),
                        timeout=1.0
                    )
                except (asyncio.TimeoutError, Exception) as e:
                    logger.warning("Failed to put QR_CHANNEL_SCANNED_WITHOUT_MULTIDEVICE in queue: %s", e)
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

            # Signal the QR emitter to stop
            self.stop_qrs.set()

            if not self.closed:
                logger.debug("Closing channel with status %s", output_type)
                try:
                    await asyncio.wait_for(
                        self.output.put(output_type),
                        timeout=1.0
                    )
                except (asyncio.TimeoutError, Exception) as e:
                    logger.warning("Failed to put final status in queue: %s", e)

                await self.close()
            else:
                logger.debug("Got status %s, but channel is already closed", output_type)
        except Exception as e:
            logger.error("Unexpected error in handle_event: %s", e, exc_info=True)


async def get_qr_channel(client: Client, max_size: int = 8) -> QRChannel:
    """
    Returns a QR channel that automatically outputs a new QR code when the previous one expires.

    This must be called *before* connect(). It will then listen to all the relevant events from the client.
    The QRChannel instance can be used as an async context manager, and its output queue can be iterated
    asynchronously to receive QR codes and events.

    The last value to be emitted will be a special event like "success", "timeout" or another error code
    depending on the result of the pairing. The channel will be closed immediately after one of those.

    Example:
        ```python
        qr_channel = await get_qr_channel(client)
        await client.connect()

        async with qr_channel as channel:
            async for item in channel:
                if item.event == "code":
                    print(f"Scan this QR code: {item.code}")
                elif item.event == "success":
                    print("Successfully paired!")
                    break
                elif item.event.startswith("err"):
                    print(f"Error: {item.event}")
                    break
        ```

    Args:
        client: The WhatsApp client instance
        max_size: Maximum size of the channel buffer

    Returns:
        A QRChannel instance that can be used as an async context manager

    Raises:
        ClientIsNilError: If the client is None
        QRAlreadyConnectedError: If the client is already connected
        QRStoreContainsIDError: If the client store already contains an ID
    """
    if client is None:
        raise ErrClientIsNil()
    if client.is_connected():
        raise ErrQRAlreadyConnected()
    if client.store.id is not None:
        raise ErrQRStoreContainsID()

    output: asyncio.Queue[QRChannelItem] = asyncio.Queue(maxsize=max_size)
    qrc = await QRChannel(
        client=client,
        output_channel=output,
    ).ainit()

    return qrc
