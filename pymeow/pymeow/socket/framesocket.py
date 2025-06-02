"""
Frame-based WebSocket implementation for WhatsApp.

Port of whatsmeow/socket/framesocket.go
"""
import asyncio
import contextlib
import logging
import struct
from typing import Optional, Callable, Awaitable, Dict, List, Any

from aiohttp import ClientSession, ClientWebSocketResponse, WSMessage, WSMsgType

from ..binary.token import DICT_VERSION
from .constants import (
    URL, ORIGIN, WA_CONN_HEADER, FRAME_MAX_SIZE, FRAME_LENGTH_SIZE,
    FrameTooLargeError, SocketClosedError, SocketAlreadyOpenError
)

logger = logging.getLogger(__name__)

class FrameSocket:
    """
    Handles frame-based WebSocket communication with WhatsApp servers.

    This class provides a frame-based abstraction over WebSocket connections,
    handling the framing protocol used by WhatsApp Web.
    """

    def __init__(self):
        """
        Initialize a new FrameSocket.

        Args:
            log: Logger to use for logging. If None, a default logger will be created.
        """
        self._ws: Optional[ClientWebSocketResponse] = None
        self._session: Optional[ClientSession] = None
        self._task: Optional[asyncio.Task] = None
        self._closed: bool = False

        self.url: str = URL
        self.http_headers: Dict[str, str] = {"Origin": ORIGIN}

        self.frames = asyncio.Queue()
        self.on_disconnect: Optional[Callable[[bool], Awaitable[None]]] = None
        self.write_timeout: Optional[float] = None

        self.header: Optional[bytes] = WA_CONN_HEADER

        # Frame processing state
        self.incoming_length: int = 0
        self.received_length: int = 0
        self.incoming: Optional[bytearray] = None
        self.partial_header: Optional[bytearray] = None

    def is_connected(self) -> bool:
        """
        Check if the socket is connected.

        Returns:
            True if the socket is connected, False otherwise
        """
        return self._ws is not None and not self._closed

    def context(self) -> Any:
        """
        Get the context for this connection.

        Returns:
            The context object
        """
        return self._task

    async def close(self, code: int = 1000) -> None:
        """
        Close the WebSocket connection.

        Args:
            code: The WebSocket close code
        """
        if self._ws is None or self._closed:
            return

        self._closed = True

        if code > 0 and self._ws is not None:
            try:
                await self._ws.close(code=code)
            except Exception as e:
                logger.warning(f"Error sending close message: {e}")

        if self._task is not None:
            self._task.cancel()
            self._task = None

        # Close the WebSocket and session
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception as e:
                logger.error(f"Error closing websocket: {e}")
            self._ws = None

        if self._session is not None:
            try:
                await self._session.close()
            except Exception as e:
                logger.error(f"Error closing session: {e}")
            self._session = None

        if self.on_disconnect:
            asyncio.create_task(self.on_disconnect(code == 0))

    async def connect(self) -> None:
        """
        Connect to WhatsApp WebSocket server.

        Raises:
            SocketAlreadyOpenError: If the socket is already open
            ConnectionError: If the connection fails
        """
        if self._ws is not None and not self._closed:
            raise SocketAlreadyOpenError()

        self._closed = False
        logger.debug(f"Dialing {self.url}")

        try:
            # Create a new session
            self._session = ClientSession()

            # Connect to the WebSocket
            self._ws = await self._session.ws_connect(self.url, headers=self.http_headers)

            # Start the receive loop
            self._task = asyncio.create_task(self._receive_loop())

        except Exception as e:
            # Clean up if connection fails
            if self._session:
                await self._session.close()
                self._session = None
            self._ws = None
            self._closed = True
            raise ConnectionError(f"Couldn't dial whatsapp web websocket: {e}") from e


    async def send_frame(self, data: bytes) -> None:
        """
        Send a frame through the WebSocket.

        Args:
            data: The frame data to send

        Raises:
            SocketClosedError: If the WebSocket is not connected
            FrameTooLargeError: If the frame is too large
        """
        if self._ws is None or self._closed:
            raise SocketClosedError()

        data_length = len(data)
        if data_length >= FRAME_MAX_SIZE:
            raise FrameTooLargeError(f"Got {data_length} bytes, max {FRAME_MAX_SIZE} bytes")

        header_length = 0 if self.header is None else len(self.header)

        # Whole frame is header + 3 bytes for length + data
        whole_frame = bytearray(header_length + FRAME_LENGTH_SIZE + data_length)

        # Copy the header if it's there
        if self.header is not None:
            logger.info(f"Prepending self.header to frame: {self.header.hex()} (raw bytes: {list(self.header)})")
            whole_frame[0:header_length] = self.header
            # We only want to send the header once
            self.header = None

        # Encode length of frame
        whole_frame[header_length] = (data_length >> 16) & 0xFF
        whole_frame[header_length + 1] = (data_length >> 8) & 0xFF
        whole_frame[header_length + 2] = data_length & 0xFF

        # Copy actual frame data
        whole_frame[header_length + FRAME_LENGTH_SIZE:] = data

        logger.info(f"Sending frame: header_length={header_length}, data_length={data_length}")
        logger.info(f"Complete frame (hex): {whole_frame.hex()}")
        logger.info(f"Complete frame length: {len(whole_frame)}")

        if self.write_timeout and self.write_timeout > 0:
            try:
                await asyncio.wait_for(self._ws.send_bytes(whole_frame), timeout=self.write_timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Write timed out after {self.write_timeout}s")
                raise
        else:
            await self._ws.send_bytes(whole_frame)

    def _frame_complete(self) -> None:
        """Handle a complete frame."""
        data = self.incoming
        self.incoming = None
        self.partial_header = None
        self.incoming_length = 0
        self.received_length = 0
        asyncio.create_task(self.frames.put(bytes(data)))

    def _process_data(self, msg: bytes) -> None:
        """
        Process incoming WebSocket data.

        Args:
            msg: The raw WebSocket message data
        """
        data = bytearray(msg)

        while len(data) > 0:
            # Handle partial header from previous message
            if self.partial_header is not None:
                data = self.partial_header + data
                self.partial_header = None

            if self.incoming is None:
                if len(data) >= FRAME_LENGTH_SIZE:
                    # Extract frame length from first 3 bytes
                    length = (data[0] << 16) + (data[1] << 8) + data[2]
                    self.incoming_length = length
                    self.received_length = len(data)
                    data = data[FRAME_LENGTH_SIZE:]

                    if len(data) >= length:
                        # We have the complete frame
                        self.incoming = data[:length]
                        data = data[length:]
                        self._frame_complete()
                    else:
                        # We have a partial frame
                        self.incoming = bytearray(length)
                        self.incoming[:len(data)] = data
                        data = bytearray()
            else:
                # We're continuing a partial frame
                if self.received_length + len(data) >= self.incoming_length:
                    # This completes the frame
                    remaining = self.incoming_length - self.received_length
                    self.incoming[self.received_length:] = data[:remaining]
                    data = data[remaining:]
                    self._frame_complete()
                else:
                    # Still not complete
                    self.incoming[self.received_length:self.received_length + len(data)] = data
                    self.received_length += len(data)
                    data = bytearray()

    async def _receive_loop(self) -> None:
        """Handle incoming WebSocket messages."""
        logger.debug(f"Frame websocket receive loop starting {id(self)}")
        ws_closed_before_loop = self._ws.closed if self._ws else "N/A"
        logger.debug(f"Initial self._ws.closed state: {ws_closed_before_loop}, self._closed flag: {self._closed}")

        try:
            async for msg in self._ws:
                logger.debug(f"Received message of type: {msg.type}")
                if msg.type == WSMsgType.BINARY:
                    logger.info(f"Received BINARY message data (hex): {msg.data.hex() if msg.data else 'None'}")
                    self._process_data(msg.data)
                elif msg.type == WSMsgType.CLOSE:
                    logger.info(f"Server closed websocket with status: {msg.data}, WebSocket close code: {self._ws.close_code}")
                    break
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error message received: {msg.data}. Exception from _ws.exception(): {self._ws.exception()}", exc_info=True)
                    break
                else:
                    logger.warning(f"Got unexpected websocket message type: {msg.type}, data: {msg.data}")
        except asyncio.CancelledError:
            logger.debug("Frame websocket receive loop cancelled (asyncio.CancelledError).")
        except Exception as e:
            if not self._closed:
                logger.error(f"Error reading from websocket: {e}", exc_info=True)
            else:
                logger.info(f"Error reading from websocket after it was already marked closed: {e}", exc_info=True)
        finally:
            ws_closed_after_loop = self._ws.closed if self._ws else "N/A"
            ws_close_code_after_loop = self._ws.close_code if self._ws else "N/A"
            ws_exception_obj_after_loop = self._ws.exception() if self._ws else None
            ws_exception_after_loop_str = str(ws_exception_obj_after_loop) if ws_exception_obj_after_loop else "N/A"

            logger.debug(
                f"Frame websocket receive loop ending. "
                f"self._ws.closed: {ws_closed_after_loop}, "
                f"self._ws.close_code: {ws_close_code_after_loop}, "
                f"self._ws.exception(): {ws_exception_after_loop_str}, "
                f"self._closed flag: {self._closed}"
            )

            if not self._closed:
                logger.info(f"Calling self.close(0) from _receive_loop finally as self._closed was False. Loop ID: {id(self)}")
                asyncio.create_task(self.close(0))
            else:
                logger.info(f"self.close(0) not called from _receive_loop finally as self._closed was True. Loop ID: {id(self)}")
