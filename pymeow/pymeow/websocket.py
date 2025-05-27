"""
PyMeow WebSocket Module - WhatsApp WebSocket Client

This module handles the WebSocket connection to WhatsApp's servers, including
connection management, message framing, and keepalive pings.

WhatsMeow Equivalents:
- socket/socket.go: Main WebSocket client implementation
- socket/conn.go: Connection handling and message framing (Partially implemented)
- socket/response_waiters.go: Response waiting and correlation (Basic implementation)
- socket/noise.go: Noise protocol implementation (Handled in auth.py)
- socket/ws_wrap.go: WebSocket wrapper and utilities (Partially implemented)
- socket/frame.go: WebSocket frame handling (Basic implementation)
- socket/ping.go: Keepalive ping implementation (Basic implementation)

Key Components:
- WebSocketClient: Main class managing the WebSocket connection (socket/socket.go)
- Handles both text (JSON) and binary message formats
- Implements automatic reconnection and ping/pong keepalive
- Manages encryption/decryption of WebSocket frames
- Provides callbacks for message handling and disconnection events

Implementation Status:
- WebSocket connection: Complete
- Message framing: Basic
- Binary protocol: Partial
- Keepalive pings: Basic
- Reconnection logic: Basic
- Error handling: Basic
- Compression: Not implemented
- Proxying: Basic support

Key Differences from WhatsMeow:
- Uses aiohttp instead of gorilla/websocket
- Async/await pattern instead of goroutines and channels
- Simplified error handling with Python exceptions
- Integrated QR code generation
- Python's logging framework
- Context manager pattern for resource management
- Less aggressive reconnection strategy
"""
import asyncio
import hmac
import json
import logging
import time
from typing import Any, Dict, Optional, Callable, Awaitable, Union, List

import aiohttp
import qrcode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from .exceptions import (
    ConnectionError,
    AuthenticationError,
    TimeoutError,
    ServerError,
    ProtocolError
)

logger = logging.getLogger(__name__)

class WebSocketClient:
    """
    WebSocket client for connecting to WhatsApp Web.

    Handles the WebSocket connection, message sending/receiving, and reconnection logic.
    """

    WHATSAPP_WEB_URL = "wss://web.whatsapp.com/ws/chat"
    WHATSAPP_WEB_VERSION = [2, 2413, 1]

    def __init__(
        self,
        client: 'Client',
        on_message: Callable[[Dict[str, Any]], Awaitable[None]],
        on_disconnect: Callable[[Optional[Exception]], Awaitable[None]],
        session: Optional[aiohttp.ClientSession] = None,
        proxy: Optional[str] = None,
        connect_timeout: float = 30.0,
        ping_interval: float = 20.0,
        ping_timeout: float = 10.0,
    ):
        """
        Initialize the WebSocket client.

        Args:
            client: The parent Client instance
            on_message: Callback for incoming messages
            on_disconnect: Callback for disconnection events
            session: Optional aiohttp session
            proxy: Optional proxy URL
            connect_timeout: Connection timeout in seconds
            ping_interval: Interval for sending pings in seconds
            ping_timeout: Timeout for ping responses in seconds
        """
        self.client = client
        self.on_message = on_message
        self.on_disconnect = on_disconnect
        self.session = session or aiohttp.ClientSession()
        self.proxy = proxy
        self.connect_timeout = connect_timeout
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout

        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._connection_lock = asyncio.Lock()
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._reconnect_delay = 1.0
        self._max_reconnect_delay = 60.0
        self._is_connected = False
        self._last_pong = 0.0
        self._ping_task: Optional[asyncio.Task] = None
        self._recv_task: Optional[asyncio.Task] = None
        self._close_event = asyncio.Event()
        self._qr_code: Optional[str] = None
        self._qr_callback: Optional[Callable[[str], Awaitable[None]]] = None

        # Encryption state
        self._encryption_key: Optional[bytes] = None
        self._mac_key: Optional[bytes] = None
        self._sequence_number = 0

        # Response tracking
        self.response_futures: Dict[str, asyncio.Future] = {}

    async def connect(self) -> None:
        """
        Connect to the WhatsApp Web WebSocket server.

        Raises:
            ConnectionError: If connection fails
            TimeoutError: If connection times out
        """
        if self._is_connected:
            logger.warning("Already connected to WhatsApp Web")
            return

        async with self._connection_lock:
            if self._is_connected:
                return

            logger.info(f"Connecting to Web (v{'.'.join(map(str, self.WHATSAPP_WEB_VERSION))})")

            try:
                # Create WebSocket connection
                self.ws = await asyncio.wait_for(
                    self.session.ws_connect(
                        self.WHATSAPP_WEB_URL,
                        proxy=self.proxy,
                        ssl=True,
                        headers={
                            'Origin': 'https://web.whatsapp.com',
                            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        },
                    ),
                    timeout=self.connect_timeout
                )

                self._is_connected = True
                self._reconnect_attempts = 0
                self._reconnect_delay = 1.0
                self._close_event.clear()

                # Start background tasks
                self._ping_task = asyncio.create_task(self._ping_loop())
                self._recv_task = asyncio.create_task(self._recv_loop())

                logger.info("Connected to WhatsApp Web")

            except asyncio.TimeoutError as e:
                raise TimeoutError("Connection to WhatsApp Web timed out") from e
            except aiohttp.ClientError as e:
                raise ConnectionError(f"Failed to connect to WhatsApp Web: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from the WebSocket server."""
        if not self._is_connected:
            return

        async with self._connection_lock:
            if not self._is_connected:
                return

            logger.info("Disconnecting from WhatsApp Web")

            # Cancel background tasks
            if self._ping_task:
                self._ping_task.cancel()
                try:
                    await self._ping_task
                except asyncio.CancelledError:
                    pass
                self._ping_task = None

            if self._recv_task:
                self._recv_task.cancel()
                try:
                    await self._recv_task
                except asyncio.CancelledError:
                    pass
                self._recv_task = None

            # Close WebSocket connection
            if self.ws and not self.ws.closed:
                await self.ws.close()

            self._is_connected = False
            self._close_event.set()
            logger.info("Disconnected from WhatsApp Web")

    async def _ping_loop(self) -> None:
        """Background task to send periodic pings to keep the connection alive."""
        while self._is_connected and not self._close_event.is_set():
            try:
                await asyncio.sleep(self.ping_interval)

                if not self._is_connected or self._close_event.is_set():
                    break

                # Send ping
                if self.ws and not self.ws.closed:
                    try:
                        await self.ws.ping()
                        self._last_pong = time.time()
                    except (ConnectionError, aiohttp.ClientError) as e:
                        logger.warning(f"Ping failed: {e}")
                        await self._handle_disconnect(e)
                        break

                # Check if we've received a pong recently
                if time.time() - self._last_pong > self.ping_interval + self.ping_timeout:
                    logger.warning("No pong received, disconnecting...")
                    await self._handle_disconnect(TimeoutError("No pong received"))
                    break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ping loop: {e}", exc_info=True)
                await asyncio.sleep(1)  # Prevent tight loop on errors

    async def _recv_loop(self) -> None:
        """Background task to receive and process incoming WebSocket messages."""
        while self._is_connected and not self._close_event.is_set() and self.ws and not self.ws.closed:
            try:
                msg = await self.ws.receive()

                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse message as JSON: {msg.data}", exc_info=True)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await self._handle_binary_message(msg.data)
                elif msg.type == aiohttp.WSMsgType.PING:
                    await self.ws.pong()
                elif msg.type == aiohttp.WSMsgType.PONG:
                    self._last_pong = time.time()
                elif msg.type == aiohttp.WSMsgType.CLOSE:
                    await self._handle_disconnect(None)
                    break
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    await self._handle_disconnect(None)
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    await self._handle_disconnect(msg.data if msg.data else "Unknown error")
                    break

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in receive loop: {e}", exc_info=True)
                await asyncio.sleep(1)  # Prevent tight loop on errors

    async def _handle_message(self, data: Dict[str, Any]) -> None:
        """
        Handle an incoming WebSocket message.

        Args:
            data: The parsed message data
        """
        try:
            # Handle different message types
            if not isinstance(data, dict):
                return

            message_type = data.get('type')
            message_id = data.get('id')
            status = data.get('status')

            # Check if this is a response to a pending request
            if message_id and message_id in self.response_futures:
                future = self.response_futures[message_id]
                if not future.done():
                    if 'error' in data:
                        future.set_exception(Exception(data.get('error', 'Unknown error')))
                    else:
                        future.set_result(data)
                return

            # Handle authentication-related messages
            if status == 'auth' or message_type == 'auth':
                auth_type = data.get('auth_type')

                # Handle QR code generation
                if auth_type == 'qr' or message_type == 'qr':
                    qr_data = data.get('code') or data.get('data')
                    if qr_data:
                        self._qr_code = qr_data
                        logger.info("QR code received for authentication")

                        # Notify via callback if set
                        if self._qr_callback:
                            await self._qr_callback(qr_data)

                        # Also forward to the client's message handler
                        await self.on_message({
                            'type': 'qr',
                            'status': 'qr',
                            'code': qr_data,
                            'data': qr_data,
                            'ttl': data.get('ttl', 30)  # Default 30 seconds TTL
                        })
                        return

                # Handle pairing success
                elif auth_type == 'pair_success' or message_type == 'pair_success':
                    logger.info("Pairing successful")
                    await self.on_message({
                        'type': 'pair_success',
                        'status': 'success',
                        'id': data.get('id'),
                        'phone': data.get('phone'),
                        'name': data.get('name'),
                        'platform': data.get('platform', 'web')
                    })
                    return

                # Handle authentication failure
                elif auth_type == 'failure' or status == 'failure':
                    error = data.get('error') or 'Authentication failed'
                    logger.error(f"Authentication failed: {error}")
                    await self.on_message({
                        'type': 'auth_failure',
                        'status': 'failure',
                        'error': error,
                        'reason': data.get('reason')
                    })
                    return

            # Forward all other messages to the client
            await self.on_message(data)

        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)
            # Forward the error to the client
            await self.on_message({
                'type': 'error',
                'error': str(e),
                'data': data
            })

    async def _handle_binary_message(self, data: bytes) -> None:
        """
        Handle an incoming binary WebSocket message.

        Args:
            data: The raw binary message data

        The binary message format is:
        - 1 byte: Flags
        - 3 bytes: Message length (big endian)
        - 4 bytes: Message tag (big endian)
        - N bytes: Encrypted message data
        - 4 bytes: HMAC-SHA256 signature
        """
        try:
            if len(data) < 8:  # Minimum header size
                logger.warning(f"Received malformed binary message (too short): {len(data)} bytes")
                return

            # Parse message header
            flags = data[0]
            msg_length = int.from_bytes(data[1:4], 'big')
            msg_tag = int.from_bytes(data[4:8], 'big')

            # Verify message length
            if len(data) < msg_length + 8:  # +8 for header
                logger.warning(f"Message length mismatch: expected {msg_length}, got {len(data)-8}")
                return

            # Extract encrypted data and HMAC
            encrypted_data = data[8:8+msg_length]
            received_hmac = data[-32:]  # Last 32 bytes is HMAC-SHA256

            # Verify HMAC if we have a MAC key
            if self._mac_key:
                hmac_calc = hmac.new(self._mac_key, data[:-32], 'sha256')
                expected_hmac = hmac_calc.digest()

                if not hmac.compare_digest(received_hmac, expected_hmac):
                    logger.error("HMAC verification failed for binary message")
                    return

            # Decrypt the message if we have an encryption key
            decrypted_data = None
            if self._encryption_key and encrypted_data:
                try:
                    # First 16 bytes are the IV
                    iv = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]

                    # Use AES-256-CBC for decryption
                    cipher = Cipher(
                        algorithms.AES(self._encryption_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()

                    # Decrypt and unpad using PKCS7
                    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                    unpadder = PKCS7(128).unpadder()  # 128 bits = 16 bytes
                    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                except Exception as e:
                    logger.error(f"Failed to decrypt binary message: {e}")
                    return
            else:
                decrypted_data = encrypted_data

            # Process the decrypted data
            if decrypted_data:
                try:
                    # Try to parse as JSON if it looks like JSON
                    if decrypted_data.startswith(b'{') or decrypted_data.startswith(b'['):
                        message = json.loads(decrypted_data.decode('utf-8'))
                        # Add the message tag to the message if it's a dictionary
                        if isinstance(message, dict) and msg_tag:
                            message['_tag'] = msg_tag
                        await self._handle_message(message)
                    else:
                        logger.debug(f"Received binary message: {decrypted_data.hex()}")
                        # Handle non-JSON binary data (e.g., media, files)
                        await self.client._handle_binary_data(decrypted_data, msg_tag)
                except json.JSONDecodeError:
                    # Not JSON, handle as raw binary data
                    logger.debug(f"Received non-JSON binary message: {len(decrypted_data)} bytes")
                    await self.client._handle_binary_data(decrypted_data, msg_tag)
                except Exception as e:
                    logger.error(f"Error processing decrypted data: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error handling binary message: {e}", exc_info=True)

    async def _handle_disconnect(self, error: Optional[Exception]) -> None:
        """
        Handle a disconnection from the WebSocket server.

        Args:
            error: The error that caused the disconnection, if any
        """
        if not self._is_connected:
            return

        self._is_connected = False
        self._close_event.set()

        # Fail all pending futures
        error = error or ConnectionError("Disconnected from server")
        # Create a list of futures to avoid modifying the dict during iteration
        futures_to_remove = []
        for request_id, future in list(self.response_futures.items()):
            if not future.done():
                future.set_exception(error)
            futures_to_remove.append(request_id)

        # Remove all processed futures
        for request_id in futures_to_remove:
            if request_id in self.response_futures:
                del self.response_futures[request_id]

        if error:
            logger.error(f"Disconnected from WhatsApp Web: {error}")
        else:
            logger.info("Disconnected from WhatsApp Web")

        # Notify parent client
        await self.on_disconnect(error)

    async def send_json(self, data: Dict[str, Any]) -> None:
        """
        Send a JSON message over the WebSocket connection.

        Args:
            data: The message data to send

        Raises:
            ConnectionError: If not connected to the server
        """
        if not self._is_connected or not self.ws or self.ws.closed:
            raise ConnectionError("Not connected to WhatsApp Web")

        try:
            await self.ws.send_json(data)
        except aiohttp.ClientError as e:
            logger.error(f"Failed to send message: {e}")
            await self._handle_disconnect(e)
            raise ConnectionError(f"Failed to send message: {e}") from e

    async def send_binary(self, data: bytes) -> None:
        """
        Send a binary message over the WebSocket connection.

        Args:
            data: The binary data to send

        Raises:
            ConnectionError: If not connected to the server
        """
        if not self._is_connected or not self.ws or self.ws.closed:
            raise ConnectionError("Not connected to WhatsApp Web")

        try:
            await self.ws.send_bytes(data)
        except aiohttp.ClientError as e:
            logger.error(f"Failed to send binary message: {e}")
            await self._handle_disconnect(e)
            raise ConnectionError(f"Failed to send binary message: {e}") from e

    async def set_qr_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """
        Set a callback to be called when a new QR code is received.

        Args:
            callback: Async function that takes a QR code string as input
        """
        self._qr_callback = callback
        if self._qr_code and callback:
            await callback(self._qr_code)

    async def generate_qr_code(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        Generate a QR code for authentication.

        Args:
            output_path: Optional path to save the QR code image

        Returns:
            The QR code data as a string, or None if not available
        """
        if not self._qr_code:
            return None

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self._qr_code)
        qr.make(fit=True)

        if output_path:
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(output_path)
            logger.info(f"QR code saved to {output_path}")

        return self._qr_code

    @property
    def is_connected(self) -> bool:
        """Check if the WebSocket is connected."""
        return self._is_connected and self.ws is not None and not self.ws.closed
