"""
Frame-based WebSocket implementation for WhatsApp.

Port of whatsmeow/socket/framesocket.go
"""
import asyncio
import contextlib
import logging
import struct
from typing import Optional, Callable, Awaitable, Dict, List, Any, Coroutine

from aiohttp import ClientSession, ClientWebSocketResponse, WSMessage, WSMsgType

from .noisesocket import NoiseSocket
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

    def __init__(self, dialer: ClientSession):
        """
        Initialize a new FrameSocket.

        Args:
            dialer: aiohttp ClientSession for WebSocket connections
        """
        self.conn: Optional[ClientWebSocketResponse] = None
        # Go: lock: sync.Mutex -> Python asyncio equivalent
        self.lock = asyncio.Lock()
        self.url: str = URL
        self.http_headers: Dict[str, str] = {"Origin": ORIGIN}
        self.frames: asyncio.Queue[bytes] = asyncio.Queue()
        self.on_disconnect: Optional[Callable[[bool], Coroutine[Any, Any, None]]] = None
        self.write_timeout: Optional[float] = None
        self.header: bytes = WA_CONN_HEADER
        self.dialer: ClientSession = dialer

        # self._task: Optional[asyncio.Task] = None


        # Frame processing state
        self.incoming_length: int = 0
        self.received_length: int = 0
        self.incoming: Optional[bytearray] = None
        self.partial_header: Optional[bytes] = None

    def is_connected(self) -> bool:
        """
        Port of Go method IsConnected from framesocket.go.

        Check if the socket is connected.

        Returns:
            True if the socket is connected, False otherwise
        """
        return self.conn is not None

    async def close(self, code: int) -> None:
        """
        Port of Go method Close from framesocket.go.

        Close the WebSocket connection with the specified close code.

        Args:
            code: The WebSocket close code. If > 0, sends a close message.
        """
        # TODO: Review websocket.FormatCloseMessage implementation
        # TODO: Review websocket.CloseMessage constant

        async with self.lock:
            if self.conn is None:
                return

            # Go: if code > 0 { ... send close message ... }
            if code > 0:
                try:
                    # Go: message := websocket.FormatCloseMessage(code, "")
                    # Go: err := fs.conn.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
                    await self.conn.close(code=code, message=b"")
                except Exception as err:
                    logger.warning(f"Error sending close message: {err}")

            # Go: err := fs.conn.Close()
            try:
                if not self.conn.closed:
                    await self.conn.close()
            except Exception as err:
                logger.error(f"Error closing websocket: {err}")

            # Go: fs.conn = nil
            self.conn = None

            # Go: if fs.OnDisconnect != nil { go fs.OnDisconnect(code == 0) }
            if self.on_disconnect is not None:
                # Go goroutine equivalent - run in background
                asyncio.create_task(self.on_disconnect(code == 0))


    async def connect(self) -> Optional[Exception]:
        """
        Port of Go method Connect from FrameSocket.

        Connect to WhatsApp WebSocket server.

        Returns:
            Optional[Exception]: None if successful, Exception if failed
        """
        # TODO: Review SocketAlreadyOpenError implementation

        async with self.lock:
            if self.conn is not None:
                return SocketAlreadyOpenError()

            logger.debug(f"Dialing {self.url}")

            try:
                self.conn = await self.dialer.ws_connect(
                    self.url,
                    headers=self.http_headers
                )

                # Start read pump
                asyncio.create_task(self.read_pump(self.conn))

                return None

            except Exception as e:
                return Exception(f"couldn't dial whatsapp web websocket: {e}")

    async def send_frame(self, data: bytes) -> Optional[Exception]:
        """
        Port of Go method SendFrame from FrameSocket.

        Send a frame through the WebSocket with proper framing protocol.

        Args:
            data: The frame data to send

        Returns:
            Optional[Exception]: None if successful, Exception if failed
        """
        if  self.conn is None:
            return SocketClosedError()

        data_length = len(data)
        if data_length >= FRAME_MAX_SIZE:
            return FrameTooLargeError(f"got {len(data)} bytes, max {FRAME_MAX_SIZE} bytes")

        header_length = len(self.header) if self.header is not None else 0
        # Whole frame is header + 3 bytes for length + data
        whole_frame = bytearray(header_length + FRAME_LENGTH_SIZE + data_length)

        # Copy the header if it's there
        if self.header is not None:
            whole_frame[:header_length] = self.header
            # We only want to send the header once
            self.header = None

        # Encode length of frame
        whole_frame[header_length] = (data_length >> 16) & 0xFF
        whole_frame[header_length + 1] = (data_length >> 8) & 0xFF
        whole_frame[header_length + 2] = data_length & 0xFF

        # Copy actual frame data
        whole_frame[header_length + FRAME_LENGTH_SIZE:] = data

        if self.write_timeout > 0:
            try:
                await asyncio.wait_for(
                    self.conn.send_bytes(whole_frame),
                    timeout=self.write_timeout
                )
                return None
            except asyncio.TimeoutError as e:
                logger.warning(f"Failed to set write deadline: {e}")
                return e
            except Exception as e:
                return e
        else:
            try:
                await self.conn.send_bytes(whole_frame)
                return None
            except Exception as e:
                return e

    def _frame_complete(self) -> None:
        """Handle a complete frame."""
        data = self.incoming
        self.incoming = None
        self.partial_header = None
        self.incoming_length = 0
        self.received_length = 0
        asyncio.create_task(self.frames.put(data)) # todo store task so it is not gc'ed

    def _process_data(self, msg: bytes) -> None:
        """
        Port of Go method processData from FrameSocket.

        Process incoming WebSocket data and reconstruct frames.

        Args:
            msg: The raw WebSocket message data
        """

        # TODO: Review FRAME_LENGTH_SIZE constant
        # TODO: Review frame_complete method implementation

        while len(msg) > 0:
            # This probably doesn't happen a lot (if at all), so the code is unoptimized
            if self.partial_header is not None:
                msg = self.partial_header + msg
                self.partial_header = None

            if self.incoming is None:
                if len(msg) >= FRAME_LENGTH_SIZE:
                    length = (int(msg[0]) << 16) + (int(msg[1]) << 8) + int(msg[2])
                    self.incoming_length = length
                    self.received_length = len(msg)
                    msg = msg[FRAME_LENGTH_SIZE:]

                    if len(msg) >= length:
                        self.incoming = msg[:length]
                        msg = msg[length:]
                        self._frame_complete()
                    else:
                        self.incoming = bytearray(length)
                        self.incoming[:len(msg)] = msg
                        msg = b''
                else:
                    logger.warning("Got partial header")
                    self.partial_header = msg
                    msg = b''
            else:
                if self.received_length + len(msg) >= self.incoming_length:
                    bytes_needed = self.incoming_length - self.received_length
                    self.incoming[self.received_length:self.received_length + bytes_needed] = msg[:bytes_needed]
                    msg = msg[bytes_needed:]
                    self._frame_complete()
                else:
                    self.incoming[self.received_length:self.received_length + len(msg)] = msg
                    self.received_length += len(msg)
                    msg = b''

    async def read_pump(self, conn: 'ClientWebSocketResponse') -> None:
        """
        Port of Go method readPump from FrameSocket.

        Continuously read messages from the WebSocket connection and process them.

        Args:
            conn: The WebSocket connection
        """
        # TODO: Review process_data method implementation
        # TODO: Review close method implementation

        logger.debug(f"Frame websocket read pump starting {id(self)}")

        try:
            async for msg in conn:
                if msg.type == WSMsgType.BINARY:
                    self._process_data(msg.data)
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"Error reading from websocket: {conn.exception()}")
                    break
                elif msg.type == WSMsgType.CLOSE:
                    logger.debug("WebSocket connection closed")
                    break
                else:
                    logger.warning(f"Got unexpected websocket message type {msg.type}")
                    continue
        except asyncio.CancelledError:
            # Ignore cancellation errors (equivalent to context.Canceled)
            pass
        except Exception as err:
            logger.error(f"Error reading from websocket: {err}")
        finally:
            logger.debug(f"Frame websocket read pump exiting {id(self)}")
            # Schedule close in background (equivalent to go fs.Close(0))
            asyncio.create_task(self.close(0))  # todo store task so it is not gc'ed
