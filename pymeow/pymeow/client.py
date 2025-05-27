"""
PyMeow Client Implementation - WhatsApp Web API Client

This module provides the main Client class that serves as the primary interface
for interacting with the WhatsApp Web API, handling authentication, message
sending/receiving, and event dispatching.

WhatsMeow Equivalents:
- client/client.go: Main Client struct and high-level functionality
- client/auth.go: Authentication and login flow
- client/client_info.go: Client info management
- client/client_misc.go: Miscellaneous client methods
- client/connect.go: Connection handling
- client/events.go: Event handling and dispatching
- client/history_sync.go: Chat history synchronization
- client/pair_phone.go: Phone number pairing flow
- client/receipts.go: Message receipt handling
- client/response_waiters.go: Response waiting utilities
- client/send.go: Message sending logic
- client/send_retry.go: Message retry mechanism
- client/upload.go: Media upload handling

Key Differences from WhatsMeow:
- Python's asyncio is used instead of Go's goroutines
- Python's context manager protocol for resource management
- Python exceptions instead of Go error returns
- Python naming conventions (snake_case)
- Type hints for better IDE support
- Dataclasses for data structures
- Async/await pattern instead of Go channels

Status:
- Core messaging: Complete
- Media handling: Partial (basic support)
- Group features: Partial
- Event system: Complete
- Message status: Partial
- Call events: Partial
- Location: Partial
- Privacy: Basic
- Newsletter: Partial

Key differences from the Go implementation:
- Uses Python's asyncio for concurrency instead of Go's goroutines
- Implements Python's context manager protocol for resource management
- Uses Python's built-in exceptions instead of Go's error returns
- Follows Python naming conventions (snake_case instead of CamelCase)
- Leverages Python's type hints for better IDE support and code clarity
- Uses dataclasses for data structures instead of Go structs
- Implements async/await pattern instead of Go channels
"""
import asyncio
import base64
import io
import json
import logging
import mimetypes
import os
import random
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable, Awaitable, Union, Tuple, TypedDict, TYPE_CHECKING

from .disappearing_messages import DisappearingMessageManager, DisappearingMessageError
from .handlers.disappearing_messages import DisappearingMessageHandler, ExpirationInfo
from .message_utils import MessageUtils
from .types.expiration import ExpirationType, ExpirationInfo

import aiohttp
from PIL import Image, ImageOps

from .protocol import ProtocolNode
# Updated imports for Protobuf classes
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
from pymeow.pymeow.generated_protos.waCommon import WACommon_pb2 # For MessageKey
from pymeow.pymeow.types import Message # This is now WAWebProtobufsE2E_pb2.Message
from pymeow.pymeow.types import MessageKey # This is now WACommon_pb2.MessageKey
from pymeow.pymeow.types import JID # For converting string JIDs to JID objects if needed by other logic
# Original type imports from .types (some might be aliased now)
from .types import Contact, Chat, GroupInfo, PrivacySetting, PrivacyValue, MessageType, MessageStatus
from .types.presence import Presence, ChatPresence, ChatPresenceMedia, PresenceEvent, ChatPresenceEvent
from .client_presence import ClientPresenceMixin
from .exceptions import PymeowError, AuthenticationError, ConnectionError
from .auth import AuthState, Device, KeyPair, NoiseHandshake, NoiseHandshakeError
from .websocket import WebSocketClient
from .rate_limiter import MessageRateLimiter
from .message_store import HistorySyncType, SyncState, ConversationInfo

logger = logging.getLogger(__name__)

class PrivacySettings(TypedDict, total=False):
    """Represents privacy settings for the user's account."""
    last_seen: PrivacySetting
    profile_photo: PrivacySetting
    status: PrivacySetting
    about: PrivacySetting
    groups: PrivacySetting
    calls: PrivacySetting


class Client(ClientPresenceMixin):
    """
    Main client class for interacting with the WhatsApp Web API.

    This class provides an async interface to WhatsApp's multi-device API,
    handling connection management, message sending/receiving, and event handling.
    """

    # Default WhatsApp Web client info
    CLIENT_INFO = {
        'platform': 'chrome',
        'app_version': '2.2413.51',
        'os_version': 'Windows 10',
        'manufacturer': 'Google',
        'device': 'Chrome',
        'os_build_number': '10.0.19043',
    }

    # WhatsApp Web API endpoints
    BASE_URL = 'https://web.whatsapp.com'
    WS_URL = 'wss://web.whatsapp.com/ws/chat'

    def __init__(
        self,
        auth_state: Optional[AuthState] = None,
        session: Optional[aiohttp.ClientSession] = None,
        log_level: int = logging.INFO,
        keepalive_interval: int = 30,
        data_dir: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the WhatsApp client.

        Args:
            auth_state: Optional AuthState instance for persistent authentication
            session: Optional aiohttp ClientSession to use for HTTP requests.
                    If not provided, one will be created automatically.
            log_level: Logging level (default: logging.INFO)
            keepalive_interval: Interval in seconds for keepalive pings
            data_dir: Directory to store persistent data (messages, etc.)
        """
        self._auth_state = auth_state or AuthState()
        self._session = session
        self._websocket = None
        self._disappearing_messages = DisappearingMessageManager()
        self._event_handlers = {
            'message': [],
            'connected': [],
            'disconnected': [],
            'authenticated': [],
            'rate_limit': [],
            'group_join': [],
            'group_leave': [],
            'error': [],
            'qr': [],
            'ready': [],
            'message_status': [],
        }

        # Initialize rate limiter with default values
        self._rate_limiter = MessageRateLimiter()
        self._rate_limiter_enabled = True
        self._log_level = log_level
        self._setup_logging()
        self._is_connected = False
        self._is_authenticated = False
        self._connection_lock = asyncio.Lock()
        self._noise_handshake = None
        self._send_cipher = None
        self._recv_cipher = None
        self._message_counter = 0
        self._pending_requests = {}
        self._keepalive_interval = keepalive_interval
        self._last_ping = 0
        self._keepalive_task = None
        self._message_epoch = 1  # Initialize message epoch counter
        self._message_status_handlers: List[Callable[[Dict[str, Any]], Awaitable[None]]] = []

        # Initialize crypto utilities
        self._crypto = self  # Use self for crypto operations

        # Initialize data directory and message store
        self._data_dir = Path(data_dir) if data_dir else Path.home() / '.pymeow'
        self._data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize message store with database path
        self._message_store = None
        self._init_message_store()

    def _init_message_store(self):
        """Initialize the message store with the configured database path."""
        if not hasattr(self, '_message_store') or self._message_store is None:
            from .message_store import MessageStore
            db_path = self._data_dir / 'messages.db'
            self._message_store = MessageStore(db_path=db_path)

        # Initialize signed pre-key
        self._signed_pre_key = None

        # Initialize identity key pair for end-to-end encryption
        self._identity_key_pair = None

        # Initialize disappearing message handler
        self._disappearing_handler = DisappearingMessageHandler(self)

        # Initialize message queue and delivery tracking
        self._message_queue = asyncio.Queue()
        self._pending_messages: Dict[str, asyncio.Future] = {}
        self._delivery_handlers: List[Callable[[Dict[str, Any]], None]] = []
        self._delivery_receipts: Dict[str, Dict[str, Any]] = {}
        self._read_receipt_handlers: List[Callable[[Dict[str, Any]], None]] = []
        self._read_receipts: Dict[str, Dict[str, Any]] = {}
        self._message_queue_task: Optional[asyncio.Task] = None
        self._retry_task: Optional[asyncio.Task] = None

        # Message history sync state
        self._history_sync_in_progress = False
        self._history_sync_lock = asyncio.Lock()
        self._last_history_sync_time = 0

    def _setup_logging(self):
        """Configure logging for the client."""
        # Clear any existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            
        # Configure logging with both console and file handlers
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # File handler
        log_file = self._data_dir / 'pymeow.log'
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self._log_level)
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
        
        # Set specific log level for aiohttp if it's too verbose
        logging.getLogger('aiohttp').setLevel(logging.WARNING)
        logging.getLogger('websockets').setLevel(logging.WARNING)
        
    async def _send_structured_node(
        self,
        to: str,
        node: 'ProtocolNode',
        expect_response: bool = False,
        timeout: Optional[float] = 30.0
    ) -> Optional['ProtocolNode']:
        """
        Send a structured protocol node to the WhatsApp server.
        
        Args:
            to: The recipient JID
            node: The ProtocolNode to send
            expect_response: Whether to wait for a response
            timeout: Timeout in seconds for waiting for a response
            
        Returns:
            The response node if expect_response is True, None otherwise
            
        Raises:
            PymeowError: If there's an error sending the node or receiving the response
        """
        if not self._websocket or not self._websocket.connected:
            raise ConnectionError("Not connected to WhatsApp servers")
            
        # Ensure we have a message ID
        if not node.attrs.get('id'):
            node.attrs['id'] = self._generate_message_id()
            
        # Set the 'to' attribute if not already set
        if not node.attrs.get('to'):
            node.attrs['to'] = to
            
        try:
            logger.debug(f"Sending structured node to {to}: {node}")
            
            # Send the node
            await self._websocket.send(node)
            
            if not expect_response:
                return None
                
            # Wait for the response
            future = asyncio.get_event_loop().create_future()
            message_id = node.attrs['id']
            self._pending_requests[message_id] = future
            
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                raise PymeowError("Timed out waiting for response") from None
            finally:
                self._pending_requests.pop(message_id, None)
                
        except Exception as e:
            logger.error(f"Error sending structured node: {e}", exc_info=True)
            raise PymeowError(f"Failed to send structured node: {e}") from e
            
    async def _dispatch_event(self, event: str, *args, **kwargs) -> None:
        """
        Dispatch an event to all registered handlers.
        
        This method ensures that:
        1. Only registered events are processed
        2. Both async and sync handlers are supported
        3. Errors in handlers don't crash the dispatcher
        4. Error events are properly handled
        
        Args:
            event: The event name to dispatch
            *args: Positional arguments to pass to handlers
            **kwargs: Keyword arguments to pass to handlers
        """
        if not event or not isinstance(event, str):
            logger.warning(f"Invalid event type: {type(event).__name__}")
            return
            
        if event not in self._event_handlers:
            logger.debug(f"No handlers registered for event: {event}")
            return
            
        handlers = self._event_handlers[event][:]  # Create a copy to avoid modification during iteration
        if not handlers:
            return
            
        logger.debug(f"Dispatching event '{event}' to {len(handlers)} handlers")
        
        for handler in handlers:
            # Get the handler name for logging at the start of the loop
            handler_name = getattr(handler, '__name__', str(handler))
            
            try:
                logger.debug(f"Calling {handler_name} for event '{event}'")
                
                # Handle both async and sync functions
                if asyncio.iscoroutinefunction(handler):
                    await handler(*args, **kwargs)
                else:
                    # Wrap sync handler in a thread
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        lambda: handler(*args, **kwargs)
                    )
                
                logger.debug(f"Successfully called {handler_name} for event '{event}'")
                
            except asyncio.CancelledError:
                logger.warning(f"Handler {handler_name} was cancelled for event '{event}'")
                raise  # Re-raise cancellation to respect task cancellation
                
            except Exception as e:
                logger.error(
                    f"Error in {handler_name} handling event '{event}': {str(e)}",
                    exc_info=True
                )
                
                # Dispatch error event but prevent infinite loops
                if event != 'error':
                    error_info = {
                        'event': event,
                        'handler': handler_name,
                        'error': str(e),
                        'type': 'event_handler_error',
                        'traceback': str(e.__traceback__)
                    }
                    try:
                        await self._dispatch_event('error', error_info)
                    except Exception as inner_e:
                        logger.critical(
                            f"Failed to dispatch error event: {inner_e}",
                            exc_info=True
                        )

    async def connect(self, sync_on_connect: bool = True, sync_type: HistorySyncType = HistorySyncType.RECENT):
        """
        Connect to WhatsApp Web API.

        This method establishes a WebSocket connection to WhatsApp Web and performs
        the authentication handshake if needed.

        Args:
            sync_on_connect: Whether to automatically sync messages after connecting
            sync_type: Type of sync to perform if sync_on_connect is True

        Raises:
            ConnectionError: If the connection fails
            AuthenticationError: If authentication fails

        Example:
            # Connect and sync recent messages
            await client.connect()

            # Connect without automatic sync
            await client.connect(sync_on_connect=False)

            # Connect and perform full sync
            from pymeow import HistorySyncType
            await client.connect(sync_type=HistorySyncType.FULL)
        """
        async with self._connection_lock:
            if self._is_connected:
                logger.warning("Already connected to WhatsApp")
                return

            try:
                # Initialize message store if not already done
                self._init_message_store()

                # Create session if not provided
                if self._session is None:
                    self._session = aiohttp.ClientSession()

                # Sync messages if requested
                if sync_on_connect and self._is_connected and self._is_authenticated:
                    asyncio.create_task(self.sync_messages(sync_type=sync_type))

                # Initialize message store
                from .message_store import MessageStore
                db_path = self._data_dir / 'messages.db'
                self._message_store = MessageStore(db_path)
                await self._message_store.initialize()

                # Perform initial sync if authenticated
                if self._auth_state and self._auth_state.logged_in:
                    await self.sync_messages(full_sync=True)

                # Initialize WebSocket connection with proper error handling
                async def handle_ws_disconnect(error: Optional[Exception] = None):
                    if error:
                        logger.error(f"WebSocket disconnected with error: {error}")
                    else:
                        logger.info("WebSocket connection closed")
                    await self._handle_ws_close()

                self._websocket = WebSocketClient(
                    client=self,
                    on_message=self._handle_ws_message,
                    on_disconnect=handle_ws_disconnect,
                    session=self._session
                )

                # Connect to WebSocket
                await self._websocket.connect()

                # Perform authentication handshake
                await self._authenticate()

                # Start background tasks
                self._start_background_tasks()

                self._is_connected = True
                logger.info("Connected to WhatsApp Web")
                await self._dispatch_event('connected')

            except Exception as e:
                logger.error(f"Connection failed: {e}")
                await self.disconnect()
                if isinstance(e, (ConnectionError, AuthenticationError)):
                    raise
                raise ConnectionError(f"Connection failed: {e}") from e

    async def disconnect(self):
        """
        Disconnect from WhatsApp Web API.

        This method gracefully closes the WebSocket connection and cleans up resources.
        """
        if not self._is_connected and not self._websocket:
            return

        async with self._connection_lock:
            try:
                # Notify event handlers
                if self._is_connected:
                    await self._dispatch_event('disconnecting')

                # Cancel all pending disappearing message tasks
                if hasattr(self, '_disappearing_handler'):
                    await self._disappearing_handler.cancel_all_tasks()

                # Stop background tasks
                self._stop_background_tasks()

                # Close WebSocket connection
                if self._websocket:
                    await self._websocket.close()
                    self._websocket = None

                # Close HTTP session if we created it
                if self._session and not self._session.closed:
                    await self._session.close()
                    self._session = None

                # Close message store
                if hasattr(self, '_message_store') and self._message_store:
                    await self._message_store.close()
                    self._message_store = None

                # Reset connection state
                self._is_connected = False
                self._is_authenticated = False
                self._noise_handshake = None
                self._send_cipher = None
                self._recv_cipher = None

                # Notify event handlers
                if self._is_connected:  # Check again in case it was modified
                    await self._dispatch_event('disconnected')
                logger.info("Disconnected from WhatsApp Web")
            except Exception as e:
                logger.error(f"Error during disconnect: {e}", exc_info=True)
                await self._dispatch_event('error', str(e))
            finally:
                # Ensure these are always reset
                self._is_connected = False
                self._is_authenticated = False

    async def send_message(
        self,
        to: str,
        content: str,
        quoted_message_id: Optional[str] = None,
        mentions: Optional[List[str]] = None,
        link_preview: bool = True,
        max_retries: int = 3,
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False
    ) -> str:
        """
        Send a text message to a chat with retry and persistence support.

        Args:
            to: Recipient JID or group JID
            content: Message content
            quoted_message_id: Optional ID of the message to quote in reply
            mentions: Optional list of JIDs to mention in the message
            link_preview: Whether to generate a link preview for URLs in the message
            max_retries: Maximum number of retry attempts for failed sends
            expiration_seconds: Duration in seconds for disappearing message (0 to disable)
            is_ephemeral: Whether this is an ephemeral (view once) message

        Returns:
            Message ID of the sent message

        Raises:
            PymeowError: If message sending fails after all retries
            ConnectionError: If not connected to WhatsApp
            ValueError: If expiration_seconds is not a valid duration
        """
        if not self._is_connected or not self._is_authenticated:
            raise ConnectionError("Not connected to WhatsApp")

        # Generate a unique message ID
        timestamp = int(time.time() * 1000)
        message_id = f"3EB0{timestamp}-{self._generate_message_id_suffix()}"

        # Add to message store before sending
        if self._message_store:
            from pymeow.pymeow.message_store import Message
            from dataclasses import field

            # Create a Message object with the required fields
            message = Message(
                message_id=message_id,
                to_jid=to,
                from_jid=f"{self._auth_state.phone_number}@s.whatsapp.net" if self._auth_state and self._auth_state.phone_number else "unknown@s.whatsapp.net",
                content=content,
                message_type='text',
                status='pending',
                retry_count=0,
                metadata={
                    'quoted_message_id': quoted_message_id,
                    'mentions': mentions,
                    'link_preview': link_preview,
                    'max_retries': max_retries,
                    'expiration_seconds': expiration_seconds,
                    'is_ephemeral': is_ephemeral
                }
            )
            await self._message_store.add_message(message)

        try:
            # Create message node using MessageUtils
            message_node = MessageUtils.create_text_message_node(
                to=to,
                content=content,
                message_id=message_id,
                quoted_message_id=quoted_message_id,
                mentions=mentions,
                expiration_seconds=expiration_seconds,
                is_ephemeral=is_ephemeral
            )

            # Add to message queue for processing
            future = asyncio.Future()
            if hasattr(self, '_message_queue'):
                await self._message_queue.put((message_id, message_node, future))

            # Wait for the message to be sent or fail
            await future
            logger.debug(f"Message {message_id} queued for sending to {to}")
            return message_id

        except asyncio.CancelledError:
            # Update status if the operation was cancelled
            if self._message_store:
                await self._message_store.update_message_status(
                    message_id=message_id,
                    status='cancelled',
                    error='Message sending was cancelled'
                )
            raise

        except Exception as e:
            error_msg = f"Failed to send message: {e}"
            logger.error(error_msg, exc_info=True)

            # Update message status in store
            if self._message_store:
                await self._message_store.update_message_status(
                    message_id=message_id,
                    status='error',
                    error=error_msg
                )

            await self._dispatch_event('error', {'error': error_msg, 'type': 'send_message'})
            raise PymeowError(error_msg) from e

    def on(self, event: str) -> Callable:
        """
        Decorator to register an event handler.

        Args:
            event: Event name to listen for

        Returns:
            Decorator function
        """
        if event not in self._event_handlers:
            raise ValueError(f"Unknown event: {event}")

        def decorator(handler: Callable[..., Awaitable[None]]):
            self._event_handlers[event].append(handler)
            return handler
        return decorator

    async def _authenticate(self):
        """
        Perform the authentication handshake with WhatsApp Web.

        This method handles the noise protocol handshake and authentication flow,
        including QR code generation and verification.

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            logger.debug("Starting authentication handshake")


            # Initialize noise handshake
            self._noise_handshake = NoiseHandshake(self._auth_state)

            # Start handshake as initiator
            handshake_msg = await self._noise_handshake.start()

            # Send initial handshake message
            await self._websocket.send_binary(handshake_msg)


            # Handle server response - this may include QR code for authentication
            response = await self._websocket.receive()
            if not response or not isinstance(response, bytes):
                raise AuthenticationError("Invalid handshake response from server")

            # Process server response - this may return a QR code or continue handshake
            response_msg = await self._noise_handshake.process_response(response)


            # If we got a QR code, emit the event and wait for scanning
            if isinstance(response, dict) and response.get('status') == 'qr':
                qr_code = response.get('code')
                if qr_code:
                    logger.info("QR code received, waiting for scan...")
                    await self._dispatch_event('qr', {'code': qr_code})
                    
                    # Wait for QR code to be scanned and pairing to complete
                    while not self._is_authenticated:
                        response = await self._websocket.receive()
                        if not response or not isinstance(response, bytes):
                            continue
                            
                        # Process the pairing response
                        try:
                            response_msg = await self._noise_handshake.process_response(response)
                            if response_msg:
                                await self._websocket.send_binary(response_msg)
                            
                            # If handshake is complete, finalize authentication
                            if self._noise_handshake.complete:
                                break
                                
                        except Exception as e:
                            logger.warning(f"Error processing pairing response: {e}")
                            continue

            # If we have a response message from the handshake, send it
            if response_msg:
                await self._websocket.send_binary(response_msg)

            # Complete the handshake
            self._send_cipher = self._noise_handshake.get_send_cipher()
            self._recv_cipher = self._noise_handshake.get_recv_cipher()

            # Mark as authenticated
            self._is_authenticated = True
            self._auth_state.logged_in = True
            logger.info("Successfully authenticated with WhatsApp Web")

            # Get user info and emit authenticated event
            user_info = await self._get_user_info()
            if user_info:
                self._auth_state.phone_number = user_info.get('phone', '')
                self._auth_state.push_name = user_info.get('name', '')
                
                # Emit pair success event
                await self._dispatch_event('pair_success', {
                    'id': user_info.get('id', ''),
                    'phone': self._auth_state.phone_number,
                    'name': self._auth_state.push_name
                })
            
            # Emit authenticated event
            await self._dispatch_event('authenticated')

        except NoiseHandshakeError as e:
            logger.error(f"Noise handshake failed: {e}", exc_info=True)
            await self._dispatch_event('auth_failure', {'error': str(e)})
            raise AuthenticationError(f"Handshake failed: {e}") from e
        except Exception as e:
            logger.error(f"Authentication failed: {e}", exc_info=True)
            await self._dispatch_event('auth_failure', {'error': str(e)})
            raise AuthenticationError(f"Authentication failed: {e}") from e

    def _start_background_tasks(self):
        """Start background tasks for message processing and maintenance."""
        # Start the message queue processor if not already running
        if not hasattr(self, '_message_queue_task') or self._message_queue_task.done():
            self._message_queue = asyncio.Queue()
            self._message_queue_task = asyncio.create_task(self._process_message_queue())

        # Start the message retry processor
        if not hasattr(self, '_retry_task') or self._retry_task.done():
            self._retry_task = asyncio.create_task(self._process_retry_queue())

    def _stop_background_tasks(self):
        """Stop all background tasks."""
        if hasattr(self, '_message_queue_task') and self._message_queue_task:
            self._message_queue_task.cancel()
        if hasattr(self, '_retry_task') and self._retry_task:
            self._retry_task.cancel()

    async def _get_user_info(self) -> Dict[str, str]:
        """
        Fetch the user's information after successful authentication.

        Returns:
            Dictionary containing user information (id, phone, name, etc.)

        Raises:
            PymeowError: If user info cannot be retrieved
        """
        try:
            # Send a request to get the user's profile
            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:profile:picture'
                }
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            user_info = {}
            if response.attrs.get('type') == 'result':
                # Extract user info from response
                user_node = response.get_child('user')
                if user_node:
                    user_info = {
                        'id': user_node.attrs.get('id', ''),
                        'phone': user_node.attrs.get('phone', ''),
                        'name': user_node.attrs.get('name', '')
                    }
            
            return user_info

        except Exception as e:
            logger.error(f"Error getting user info: {e}", exc_info=True)
            raise PymeowError(f"Failed to get user info: {e}") from e

    def generate_qr_code(self, qr_data: str = None, output_path: str = None, show_console: bool = True) -> Optional[str]:
        """
        Generate and optionally display a QR code for authentication.

        Args:
            qr_data: The QR code data to generate. If None, uses the last received QR code.
            output_path: Optional path to save the QR code image.
            show_console: Whether to display the QR code in the console.

        Returns:
            The QR code data as a string, or None if no QR code is available.
        """
        try:
            import qrcode
            from qrcode.image.pure import PymagingImage
            
            # Use provided data or last received QR code
            qr_data = qr_data or (self._websocket._qr_code if hasattr(self, '_websocket') and self._websocket else None)
            if not qr_data:
                logger.warning("No QR code data available")
                return None
                
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            # Save to file if path is provided
            if output_path:
                try:
                    img = qr.make_image(fill_color="black", back_color="white")
                    img.save(output_path)
                    logger.info(f"QR code saved to {output_path}")
                except Exception as e:
                    logger.error(f"Failed to save QR code: {e}", exc_info=True)
            
            # Display in console if requested
            if show_console:
                try:
                    qr.print_ascii(invert=True)
                    print(f"\nScan the QR code above to authenticate with WhatsApp Web")
                    print(f"Or use this link: https://web.whatsapp.com/device {qr_data}")
                except Exception as e:
                    logger.warning(f"Failed to display QR code in console: {e}")
            
            return qr_data
            
        except ImportError:
            logger.error("qrcode package is required to generate QR codes. Install with: pip install qrcode[pil]")
            return None
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}", exc_info=True)
            return None

    def set_qr_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """
        Set a callback function to be called when a new QR code is received.

        Args:
            callback: An async function that takes a QR code string as input.
                     The function will be called with the QR code data whenever
                     a new one is received from the server.
        """
        if hasattr(self, '_websocket') and self._websocket:
            self._websocket.set_qr_callback(callback)
        else:
            logger.warning("WebSocket not initialized, QR callback not set")

    async def _process_retry_queue(self):
        """Process messages that need to be retried.

        This method implements an exponential backoff with jitter strategy for
        retrying failed messages. It periodically checks for messages that need
        to be retried and adds them back to the message queue for processing.

        The retry strategy uses the following parameters (configurable per message):
        - base_delay: Initial delay between retries (default: 30s)
        - max_retries: Maximum number of retry attempts (default: 5)
        - max_delay: Maximum delay between retries (default: 1 hour)
        - backoff_factor: Multiplier for exponential backoff (default: 2.0)
        - jitter: Whether to add random jitter to delays (default: True)
        """
        # Default retry configuration
        DEFAULT_RETRY_CONFIG = {
            'base_delay': 30.0,      # 30 seconds initial delay
            'max_retries': 5,        # Max 5 retry attempts
            'max_delay': 3600.0,     # Max 1 hour between retries
            'backoff_factor': 2.0,   # Exponential backoff factor
            'jitter': True,          # Add jitter to spread out retries
            'jitter_min': 0.5,       # Minimum jitter factor (0.5 = 50% of delay)
            'jitter_max': 1.5,       # Maximum jitter factor (1.5 = 150% of delay)
        }


        while True:
            try:
                if not self._is_connected:
                    await asyncio.sleep(1)
                    continue

                # Only proceed if we have a message store and queue
                if not self._message_store or not hasattr(self, '_message_queue') or not self._message_queue:
                    await asyncio.sleep(DEFAULT_RETRY_CONFIG['base_delay'])
                    continue

                # Get messages that need retrying (failed or timed out)
                pending_messages = await self._message_store.get_pending_messages(
                    limit=10,  # Process in batches of 10
                    statuses=['error', 'timeout']
                )

                if not pending_messages:
                    # No messages to retry, wait before checking again
                    await asyncio.sleep(DEFAULT_RETRY_CONFIG['base_delay'])
                    continue

                logger.info(f"Found {len(pending_messages)} messages to retry")

                current_time = time.time()

                for message in pending_messages:
                    try:
                        # Get message-specific retry config or use defaults
                        retry_config = {
                            **DEFAULT_RETRY_CONFIG,
                            **getattr(message, 'retry_config', {})
                        }


                        # Check max retries
                        if message.retry_count >= retry_config['max_retries']:
                            await self._handle_message_status_update(
                                message.message_id,
                                'failed',
                                f'Max retries ({message.retry_count}) exceeded'
                            )
                            continue

                        # Create a new message node for retry
                        message_node = ProtocolNode(
                            tag='message',
                            attrs={
                                'id': message.message_id,
                                'to': message.to_jid,
                                'type': message.message_type or 'text',
                                'retry': str(message.retry_count + 1)  # Include retry count
                            },
                            content=[
                                ProtocolNode('body', content=message.content)
                            ]
                        )

                        # Calculate next retry delay with exponential backoff and jitter
                        delay = self._calculate_retry_delay(
                            retry_count=message.retry_count,
                            base_delay=retry_config['base_delay'],
                            max_delay=retry_config['max_delay'],
                            backoff_factor=retry_config['backoff_factor'],
                            jitter=retry_config['jitter'],
                            jitter_min=retry_config['jitter_min'],
                            jitter_max=retry_config['jitter_max']
                        )

                        # Add any additional metadata from the original message
                        metadata = getattr(message, 'metadata', {}) or {}
                        if 'quoted_message_id' in metadata:
                            quoted_node = ProtocolNode(
                                tag='quoted',
                                attrs={'id': metadata['quoted_message_id']}
                            )
                            message_node.add_child(quoted_node)

                        if 'mentions' in metadata and metadata['mentions']:
                            mention_nodes = [
                                ProtocolNode('mention', attrs={'jid': jid})
                                for jid in metadata['mentions']
                            ]
                            mentions_node = ProtocolNode('mentions', content=mention_nodes)
                            message_node.add_child(mentions_node)

                        # Add next retry time to metadata
                        next_retry_time = current_time + delay
                        metadata.update({
                            'next_retry_time': next_retry_time,
                            'retry_delay': delay,
                            'retry_attempt': message.retry_count + 1
                        })

                        # Add to message queue for processing with a new future
                        future = asyncio.Future()
                        await self._message_queue.put((message.message_id, message_node, future))

                        # Update status to 'retrying' with the new retry count
                        await self._handle_message_status_update(
                            message_id=message.message_id,
                            status='retrying',
                            error=None
                        )

                        logger.debug(
                            f"Scheduled retry {message.retry_count + 1} for message {message.message_id} "
                            f"(delay: {delay:.1f}s, next: {next_retry_time - current_time:.1f}s)"
                        )

                    except Exception as e:
                        logger.error(f"Error scheduling retry for message {message.message_id}: {e}", exc_info=True)
                        # Update status to indicate the retry scheduling failed
                        await self._handle_message_status_update(
                            message_id=message.message_id,
                            status='error',
                            error=f'Failed to schedule retry: {str(e)}'
                        )

                # Wait before checking for more messages to retry
                await asyncio.sleep(DEFAULT_RETRY_CONFIG['base_delay'])

            except asyncio.CancelledError:
                logger.info("Retry processor was cancelled")
                break

            except Exception as e:
                logger.error(f"Error in retry processor: {e}", exc_info=True)
                # Use exponential backoff for error retries as well
                error_delay = min(5 * (2 ** min(5, self._retry_errors)), 300)  # Max 5 minutes
                self._retry_errors = getattr(self, '_retry_errors', 0) + 1
                await asyncio.sleep(error_delay)

    def _calculate_retry_delay(
        self,
        retry_count: int,
        base_delay: float = 30.0,
        max_delay: float = 3600.0,
        backoff_factor: float = 2.0,
        jitter: bool = True,
        jitter_min: float = 0.5,
        jitter_max: float = 1.5
    ) -> float:
        """Calculate the delay for a retry attempt using exponential backoff with jitter.

        Args:
            retry_count: The current retry attempt number (0-based)
            base_delay: Base delay in seconds
            max_delay: Maximum delay in seconds
            backoff_factor: Multiplier for exponential backoff
            jitter: Whether to add jitter to the delay
            jitter_min: Minimum jitter factor (multiplier)
            jitter_max: Maximum jitter factor (multiplier)

        Returns:
            The calculated delay in seconds
        """
        # Reset error counter on successful retry
        self._retry_errors = 0

        # Calculate exponential backoff
        delay = min(
            base_delay * (backoff_factor ** retry_count),
            max_delay
        )

        # Add jitter if enabled
        if jitter and retry_count > 0:
            jitter_factor = random.uniform(jitter_min, jitter_max)
            delay = min(float(delay * jitter_factor), float(max_delay))

        return max(0.0, delay)

    # Rate Limiter Control Methods

    def enable_rate_limiting(self, enabled: bool = True) -> None:
        """Enable or disable rate limiting for message sending.

        Args:
            enabled: Whether to enable rate limiting
        """
        self._rate_limiter_enabled = enabled
        logger.info(f"Rate limiting {'enabled' if enabled else 'disabled'}")

    def set_rate_limits(self, global_rate: Optional[float] = None,
                       global_capacity: Optional[int] = None,
                       per_recipient_rate: Optional[float] = None,
                       per_recipient_capacity: Optional[int] = None) -> None:
        """Update rate limiting parameters.

        Args:
            global_rate: Global messages per second (None to keep current)
            global_capacity: Global burst capacity (None to keep current)
            per_recipient_rate: Per-recipient messages per second (None to keep current)
            per_recipient_capacity: Per-recipient burst capacity (None to keep current)
        """
        if global_rate is not None or global_capacity is not None:
            if hasattr(self._rate_limiter, 'global_limiter'):
                if global_rate is not None:
                    self._rate_limiter.global_limiter.rate = global_rate
                if global_capacity is not None:
                    self._rate_limiter.global_limiter.capacity = global_capacity

                logger.info(f"Updated global rate limits: rate={global_rate or 'unchanged'}, "
                            f"capacity={global_capacity or 'unchanged'}")

        if per_recipient_rate is not None or per_recipient_capacity is not None:
            if hasattr(self._rate_limiter, 'per_recipient_limiters'):
                # Update the default values for new limiters
                if per_recipient_rate is not None:
                    self._rate_limiter.per_recipient_rate = per_recipient_rate
                if per_recipient_capacity is not None:
                    self._rate_limiter.per_recipient_capacity = per_recipient_capacity

                # Update all existing limiters
                for limiter in self._rate_limiter.per_recipient_limiters.values():
                    if per_recipient_rate is not None:
                        limiter.rate = per_recipient_rate
                    if per_recipient_capacity is not None:
                        limiter.capacity = per_recipient_capacity

                logger.info(f"Updated per-recipient rate limits: rate={per_recipient_rate or 'unchanged'}, "
                            f"capacity={per_recipient_capacity or 'unchanged'}")

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get the current rate limiting status.

        Returns:
            Dictionary with rate limiting status information
        """
        status = {
            'enabled': self._rate_limiter_enabled,
            'global': {},
            'per_recipient': {}
        }

        if hasattr(self._rate_limiter, 'global_limiter'):
            status['global'].update({
                'rate': self._rate_limiter.global_limiter.rate,
                'capacity': self._rate_limiter.global_limiter.capacity,
                'tokens': self._rate_limiter.global_limiter.tokens,
                'updated_at': self._rate_limiter.global_limiter.updated_at
            })

        if hasattr(self._rate_limiter, 'per_recipient_limiters'):
            status['per_recipient'].update({
                'rate': getattr(self._rate_limiter, 'per_recipient_rate', 'N/A'),
                'capacity': getattr(self._rate_limiter, 'per_recipient_capacity', 'N/A'),
                'active_recipients': len(self._rate_limiter.per_recipient_limiters)
            })

        return status

    async def _process_message_queue(self):
        """Process messages from the send queue.

        This method processes messages in the queue, handles sending, and manages retries
        for failed messages using the message store for persistence.
        """
        while True:
            try:
                if not hasattr(self, '_message_queue') or self._message_queue is None:
                    await asyncio.sleep(1)
                    continue

                message_id, message_node, future = await self._message_queue.get()

                try:
                    # Get recipient JID for rate limiting
                    recipient_jid = message_node.attrs.get('to')

                    # Apply rate limiting if enabled
                    if self._rate_limiter_enabled and recipient_jid:
                        try:
                            await self._rate_limiter.acquire(recipient_jid)
                        except Exception as e:
                            logger.warning(f"Rate limit exceeded for {recipient_jid}: {e}")
                            # Dispatch rate limit event
                            await self._dispatch_event('rate_limit', {
                                'recipient_jid': recipient_jid,
                                'message_id': message_id,
                                'timestamp': int(time.time() * 1000),
                                'error': str(e)
                            })
                            # Wait a bit before retrying
                            await asyncio.sleep(1)
                            # Requeue the message
                            await self._message_queue.put((message_id, message_node, future))
                            continue

                    # Update status to 'sending' before attempting to send
                    await self._handle_message_status_update(message_id, 'sending')

                    # Send the message
                    await self._send_node(message_node)

                    # Update status to 'sent' after successful send
                    await self._handle_message_status_update(message_id, 'sent')

                    # Complete the future
                    if not future.done():
                        future.set_result(True)

                except asyncio.CancelledError:
                    # Handle cancellation
                    await self._handle_message_status_update(
                        message_id,
                        'cancelled',
                        'Message sending was cancelled'
                    )
                    if not future.done():
                        future.cancel()
                    raise

                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"Error sending message {message_id}: {error_msg}", exc_info=True)

                    # Update status to 'error' and handle retry logic
                    await self._handle_message_status_update(
                        message_id,
                        'error',
                        error=error_msg
                    )

                    # Complete the future with error
                    if not future.done():
                        future.set_exception(e)

                finally:
                    # Mark the task as done in the queue
                    if hasattr(self, '_message_queue') and self._message_queue:
                        self._message_queue.task_done()

            except asyncio.CancelledError:
                logger.info("Message queue processor was cancelled")
                break

            except Exception as e:
                logger.error(f"Error in message queue processor: {e}", exc_info=True)
                await asyncio.sleep(1)  # Prevent tight error loops

    async def sync_messages(
        self,
        sync_type: HistorySyncType = HistorySyncType.FULL,
        chat_jid: Optional[str] = None,
        count: int = 100,
        cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sync message history from the server.

        Args:
            sync_type: Type of sync to perform (FULL, RECENT, etc.)
            chat_jid: Optional chat JID to sync messages for (if None, syncs all chats)
            count: Number of messages to sync (for pagination)
            cursor: Pagination cursor from previous sync

        Returns:
            Dictionary containing sync results including status and cursor for pagination

        Example:
            # Sync recent messages
            result = await client.sync_messages(sync_type=HistorySyncType.RECENT)

            # Sync messages for a specific chat
            result = await client.sync_messages(chat_jid='1234567890@s.whatsapp.net')
        """
        if not self._is_connected:
            raise ConnectionError("Not connected to WhatsApp")

        # Get current sync state
        sync_state = await self.get_sync_state(sync_type)

        # Prepare sync request parameters
        params = {
            'mode': 'full',
            'context': 'notification',
            'index': '0',
            'last': 'true',
            'sid': str(int(time.time())),
            'batch_size': str(count)
        }

        if cursor:
            params['cursor'] = cursor

        if chat_jid:
            params['chat_jid'] = chat_jid

        try:
            # Create sync node
            sync_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': self._generate_message_id(),
                    'type': 'get',
                    'to': 's.whatsapp.net',
                    'xmlns': 'urn:xmpp:whatsapp:sync'
                },
                content=[
                    ProtocolNode('sync', attrs=params)
                ]
            )

            # Send sync request
            response = await self._send_iq_and_wait(sync_node, iq_id=sync_node.attrs.get('id', str(uuid.uuid4())))

            # Process the response
            if response and response.attrs.get('type') == 'result':
                sync_result = {
                    'success': True,
                    'has_more': False,
                    'cursor': None,
                    'synced_messages': 0,
                    'synced_chats': 0,
                    'sync_type': sync_type.name
                }

                # Check for sync result data
                sync_result_nodes = response.find_all('sync')
                if sync_result_nodes:
                    sync_result_node = sync_result_nodes[0]  # Get first sync node if multiple exist
                    sync_result.update({
                        'has_more': sync_result_node.attrs.get('has_more', 'false').lower() == 'true',
                        'cursor': sync_result_node.attrs.get('cursor')
                    })

                    # Update sync state with new cursor if provided
                    if 'cursor' in sync_result_node.attrs:
                        await self.update_sync_state(
                            sync_type=sync_type,
                            sync_cursor=sync_result_node.attrs['cursor'],
                            last_sync_timestamp=time.time()
                        )

                logger.info(f"Successfully synced {sync_type.name} messages")
                return sync_result

            else:
                error_msg = f"Failed to sync messages: {response.attrs.get('error') if response else 'Unknown error'}"
                logger.error(error_msg)
                return {
                    'success': False,
                    'error': error_msg,
                    'sync_type': sync_type.name
                }

        except Exception as e:
            error_msg = f"Error during message sync: {e}"
            logger.error(error_msg, exc_info=True)
            return {
                'success': False,
                'error': error_msg,
                'sync_type': sync_type.name
            }

    async def get_conversations(
        self,
        limit: int = 50,
        before: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Get list of conversations with their latest messages.

        Args:
            limit: Maximum number of conversations to return (default: 50)
            before: Only return conversations before this timestamp (for pagination)

        Returns:
            List of conversation dictionaries with metadata

        Example:
            # Get first 20 conversations
            conversations = await client.get_conversations(limit=20)

            # Get next page of conversations
            last_timestamp = conversations[-1]['last_message_timestamp']
            more_conversations = await client.get_conversations(before=last_timestamp)
        """
        if not hasattr(self, '_message_store') or not self._message_store:
            return []

        return await self._message_store.get_conversations(limit=limit, before=before)

    async def get_sync_state(self, sync_type: HistorySyncType) -> Dict[str, Any]:
        """
        Get the current sync state for a specific sync type.

        Args:
            sync_type: The type of sync to get state for

        Returns:
            Dictionary containing sync state information including:
            - last_sync_timestamp: When the last sync occurred
            - sync_cursor: Current pagination cursor
            - progress: Sync progress percentage (0-100)
            - sync_type: The type of sync this state is for
        """
        if not hasattr(self, '_message_store') or not self._message_store:
            return {
                'last_sync_timestamp': 0,
                'sync_cursor': None,
                'progress': 0,
                'sync_type': sync_type.name
            }

        return await self._message_store.get_sync_state(sync_type)

    async def update_sync_state(
        self,
        sync_type: HistorySyncType,
        last_sync_timestamp: Optional[float] = None,
        sync_cursor: Optional[str] = None,
        progress: Optional[int] = None
    ) -> None:
        """
        Update the sync state for a specific sync type.

        Args:
            sync_type: The type of sync to update
            last_sync_timestamp: When the sync occurred
            sync_cursor: Current pagination cursor
            progress: Sync progress percentage (0-100)
        """
        if hasattr(self, '_message_store') and self._message_store:
            await self._message_store.update_sync_state(
                sync_type=sync_type,
                last_sync_timestamp=last_sync_timestamp,
                sync_cursor=sync_cursor,
                progress=progress
            )

    async def get_conversation_info(self, chat_jid: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a conversation.

        Args:
            chat_jid: The JID of the chat to get info for

        Returns:
            Dictionary with conversation details or None if not found

        Example:
            # Get info for a specific chat
            chat_info = await client.get_conversation_info('1234567890@s.whatsapp.net')
            if chat_info:
                print(f"Chat name: {chat_info.get('name')}")
                print(f"Last message: {chat_info.get('last_message', {}).get('content')}")
        """
        if not hasattr(self, '_message_store') or not self._message_store:
            self._init_message_store()
            if not self._message_store:
                return None

        # Get conversations and filter by chat_jid
        conversations = await self._message_store.get_conversations(limit=1000)  # Large limit to ensure we find the chat
        for conv in conversations:
            if isinstance(conv, dict) and conv.get('chat_jid') == chat_jid:
                return conv

        # If not found, try to sync and check again
        await self.sync_messages(chat_jid=chat_jid, count=1)

        # Check again after sync
        conversations = await self._message_store.get_conversations(limit=1000)
        for conv in conversations:
            if isinstance(conv, dict) and conv.get('chat_jid') == chat_jid:
                return conv

        return None

    async def _handle_history_sync(self, sync_data: Dict[str, Any]) -> None:
        """
        Handle history sync data from the server.

        Args:
            sync_data: Dictionary containing sync data from the server
        """
        if not sync_data:
            return

        sync_type = sync_data.get('sync_type')
        if sync_type is None:
            logger.warning("Received history sync with no type")
            return

        try:
            # Process the sync data in the message store
            if hasattr(self, '_message_store') and self._message_store:
                await self._message_store.handle_history_sync(sync_data)

                # Dispatch sync complete event
                await self._dispatch_event('history_sync', {
                    'type': sync_type,
                    'conversations_count': len(sync_data.get('conversations', [])),
                    'status_messages_count': len(sync_data.get('statusV3Messages', [])),
                    'timestamp': time.time()
                })

                logger.info(f"Processed history sync: {sync_type} with "
                          f"{len(sync_data.get('conversations', []))} conversations")
            else:
                logger.warning("Message store not initialized, cannot process history sync")

        except Exception as e:
            logger.error(f"Error processing history sync: {e}", exc_info=True)
            await self._dispatch_event('history_sync_error', {
                'error': str(e),
                'sync_type': sync_type,
                'timestamp': time.time()
            })

    async def _handle_ws_message(self, message: Dict[str, Any]) -> None:
        """
        Handle incoming WebSocket messages.

        Args:
            message: The received WebSocket message as a dictionary
        """
        try:
            # Process the message based on its type
            message_type = message.get('type')

            if message_type == 'binary':
                # Handle binary message (encrypted)
                if not self._recv_cipher:
                    logger.warning("Received encrypted message before handshake completion")
                    return

                try:
                    # Extract binary data from message
                    binary_data = base64.b64decode(message.get('data', ''))
                    decrypted = self._recv_cipher.decrypt(binary_data)
                    await self._process_message(decrypted)
                except Exception as e:
                    logger.error(f"Failed to decrypt message: {e}", exc_info=True)

            elif message_type == 'json':
                # Handle JSON message
                data = message.get('data', {})
                if not isinstance(data, dict):
                    logger.warning(f"Received invalid JSON message: {message}")
                    return
                await self._process_json_message(data)

            else:
                # Forward other message types to the appropriate handler
                logger.debug(f"Received message of type {message_type}")
                await self._dispatch_event('websocket_message', message)

        except Exception as e:
            logger.error(f"Error processing WebSocket message: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'message_processing'})

    async def _handle_ws_close(self):
        """Handle WebSocket connection close."""
        logger.info("WebSocket connection closed")
        self._is_connected = False
        self._is_authenticated = False
        await self._dispatch_event('disconnected')

    async def _handle_ws_error(self, error: Exception):
        """
        Handle WebSocket error.

        Args:
            error: The exception that occurred
        """
        logger.error(f"WebSocket error: {error}", exc_info=True)
        await self._dispatch_event('error', {'error': str(error)})

    async def _process_message(self, message: bytes):
        """
        Process a decrypted binary message.

        Args:
            message: The decrypted message bytes

        The message format is:
        - 1 byte: Flags
        - 4 bytes: Message tag (big-endian)
        - 4 bytes: Message length (big-endian)
        - N bytes: Message payload
        """
        try:
            if len(message) < 9:  # Minimum message size (1 + 4 + 4)
                logger.warning(f"Received message too short: {len(message)} bytes")
                return

            # Parse message header
            flags = message[0]
            tag = int.from_bytes(message[1:5], 'big')
            length = int.from_bytes(message[5:9], 'big')

            if len(message) < 9 + length:
                logger.warning(f"Message length mismatch: expected {length}, got {len(message)-9}")
                return

            payload = message[9:9+length]

            # Handle different message types based on flags
            if flags & 0x80:  # Server message
                await self._handle_server_message(tag, payload)
            else:
                # Client message, check if it's a response to a request
                if tag in self._pending_requests:
                    future = self._pending_requests.pop(tag)
                    future.set_result(payload)
                else:
                    logger.debug(f"Received unexpected message with tag {tag}")

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'message_processing'})

    def _process_sync_response(self, response: Union[ProtocolNode, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process a sync response from the server.

        Args:
            response: The response data, either as a ProtocolNode or dict

        Returns:
            Dictionary containing processed sync data
        """
        result = {
            'messages': [],
            'contacts': [],
            'chats': [],
            'stats': {
                'total_messages': 0,
                'total_contacts': 0,
                'total_chats': 0,
                'new_messages': 0,
                'new_contacts': 0,
                'new_chats': 0
            }
        }


        # If response is already a dict, return it as is
        if isinstance(response, dict):
            return response

        # Process ProtocolNode response
        if not isinstance(response.content, list):
            return result

        for child in response.content:
            if not isinstance(child, ProtocolNode):
                continue

            if child.tag == 'sync':
                if not isinstance(child.content, list):
                    continue

                for collection in child.content:
                    if not isinstance(collection, ProtocolNode) or collection.tag != 'collection':
                        continue

                    name = collection.attrs.get('name', '')
                    count = int(collection.attrs.get('count', '0'))

                    if name == 'message':
                        result['stats']['total_messages'] = count
                        # Process messages
                        if not isinstance(collection.content, list):
                            continue

                        for msg_node in collection.content:
                            if isinstance(msg_node, ProtocolNode) and msg_node.tag == 'message':
                                msg = self._process_sync_message(msg_node)
                                if msg:
                                    result['messages'].append(msg)
                                    result['stats']['new_messages'] += 1

                    elif name == 'contact':
                        result['stats']['total_contacts'] = count
                        # Process contacts
                        if not isinstance(collection.content, list):
                            continue

                        for contact_node in collection.content:
                            if isinstance(contact_node, ProtocolNode) and contact_node.tag == 'contact':
                                contact = self._process_sync_contact(contact_node)
                                if contact:
                                    result['contacts'].append(contact)
                                    result['stats']['new_contacts'] += 1

                    elif name == 'chat':
                        result['stats']['total_chats'] = count
                        # Process chats
                        if not isinstance(collection.content, list):
                            continue

                        for chat_node in collection.content:
                            if isinstance(chat_node, ProtocolNode) and chat_node.tag == 'chat':
                                chat = self._process_sync_chat(chat_node)
                                if chat:
                                    result['chats'].append(chat)
                                    result['stats']['new_chats'] += 1

        return result

    def _process_sync_message(self, node: ProtocolNode) -> Optional[Dict[str, Any]]:
        """Process a message node from sync response."""
        try:
            msg = {
                'id': node.attrs.get('id'),
                'from': node.attrs.get('from'),
                'to': node.attrs.get('to'),
                'timestamp': int(node.attrs.get('t', '0')),
                'type': node.attrs.get('type'),
                'is_group': node.attrs.get('participant') is not None,
                'participant': node.attrs.get('participant'),
                'content': {}
            }

            # Process message content
            if isinstance(node.content, list):
                for child in node.content:
                    if not isinstance(child, ProtocolNode):
                        continue

                    if child.tag == 'body':
                        # Handle both string content and node with content attribute
                        if hasattr(child, 'content'):
                            msg['content']['text'] = child.content
                        elif hasattr(child, 'text'):
                            msg['content']['text'] = child.text
                    elif child.tag == 'media':
                        msg['content'].update({
                            'media_type': child.attrs.get('type'),
                            'media_url': child.attrs.get('url'),
                            'mimetype': child.attrs.get('mimetype'),
                            'file_length': int(child.attrs.get('file_length', '0')),
                            'file_sha256': child.attrs.get('file_sha256'),
                            'caption': child.attrs.get('caption')
                        })

            # Store message in local database
            if self._message_store:
                asyncio.create_task(self._store_message(msg))

            return msg

        except Exception as e:
            logger.error(f"Error processing sync message: {e}", exc_info=True)
            return None

    async def _store_message(self, msg: Dict[str, Any]) -> bool:
        """Store a message in the local database."""
        if not self._message_store:
            return False

        try:
            # Ensure we have a message ID
            message_id = msg.get('id')
            if not message_id:
                logger.warning("Cannot store message: missing message ID")
                return False

            # Get the chat ID (use 'from' for received messages, 'to' for sent)
            chat_id = msg.get('from') or msg.get('to', '')
            if not chat_id:
                logger.warning("Cannot store message: missing chat ID")
                return False

            # Create message info
            message_key = MessageKey(
                id=message_id,
                remote_jid=JID.from_string(chat_id) if isinstance(chat_id, str) else chat_id,
                from_me=bool(msg.get('from_me', False))
            )

            message_info = MessageInfo(
                key=message_key,
                message_timestamp=int(datetime.now().timestamp()),
                status=MessageStatus.PENDING
            )

            # Create the message object with required fields
            message = Message(
                info=message_info,
                message=msg.get('content', {}),
                message_type=MessageType.TEXT  # Default to TEXT, adjust as needed
            )

            # Add the message to the store
            await self._message_store.add_message(message)
            return True

        except Exception as e:
            logger.error(f"Error storing message: {e}", exc_info=True)
            return False

    def _process_sync_contact(self, node: ProtocolNode) -> Optional[Dict[str, Any]]:
        """Process a contact node from sync response."""
        try:
            return {
                'jid': node.attrs.get('jid'),
                'name': node.attrs.get('name'),
                'notify': node.attrs.get('notify'),
                'vname': node.attrs.get('vname'),
                'short': node.attrs.get('short')
            }
        except Exception as e:
            logger.error(f"Error processing sync contact: {e}", exc_info=True)
            return None

    def _process_sync_chat(self, node: ProtocolNode) -> Optional[Dict[str, Any]]:
        """Process a chat node from sync response."""
        try:
            return {
                'jid': node.attrs.get('jid'),
                'name': node.attrs.get('name'),
                'count': int(node.attrs.get('count', '0')),
                't': int(node.attrs.get('t', '0')),
                'mute': node.attrs.get('mute'),
                'pin': node.attrs.get('pin'),
                'spam': node.attrs.get('spam')
            }
        except Exception as e:
            logger.error(f"Error processing sync chat: {e}", exc_info=True)
            return None

    async def _wait_for_sync_response(self, request_id: str, timeout: float = 30.0) -> Optional[Dict[str, Any]]:
        """
        Wait for a response to a sync request.

        Args:
            request_id: The ID of the request we're waiting for
            timeout: Maximum time to wait in seconds

        Returns:
            The response data if received, None otherwise
        """
        if not self._websocket or not hasattr(self._websocket, 'response_futures'):
            return None

        # Create a future to wait for the response
        future = asyncio.get_event_loop().create_future()
        self._websocket.response_futures[request_id] = future

        try:
            # Wait for the response with timeout
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Timeout waiting for sync response {request_id}")
            return None
        except Exception as e:
            logger.error(f"Error waiting for sync response: {e}", exc_info=True)
            return None
        finally:
            # Clean up the future
            if hasattr(self, '_websocket') and hasattr(self._websocket, 'response_futures'):
                self._websocket.response_futures.pop(request_id, None)


    async def _process_json_message(self, data: Dict[str, Any]):
        """
        Process a JSON message from the WebSocket.

        Args:
            data: The parsed JSON message

        The JSON message can be one of several types:
        - Message notifications
        - Presence updates
        - Connection state changes
        - Etc.
        """
        try:
            if not isinstance(data, dict):
                logger.warning(f"Received non-dict JSON message: {data}")
                return

            # Extract common fields
            message_type = data.get('type')
            message_id = data.get('id')

            # Log the message for debugging
            logger.debug(f"Received message (type={message_type}): {json.dumps(data, indent=2)}")

            # Handle different message types
            if message_type == 'message':
                await self._handle_message_notification(data)
            elif message_type == 'presence':
                await self._handle_presence_update(data)
            elif message_type == 'chat':
                await self._handle_chat_update(data)
            elif message_type == 'call':
                await self._handle_call_notification(data)
            elif message_type == 'contacts':
                await self._handle_contacts_update(data)
            else:
                # Forward unknown message types to generic handler
                await self._dispatch_event('json_message', data)

        except Exception as e:
            logger.error(f"Error processing JSON message: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'json_processing'})

    async def _handle_message_notification(self, data: Dict[str, Any]):
        """Handle an incoming message notification."""
        try:
            # Store the message in the message store
            if self._message_store and 'id' in data and 'from' in data:
                message = {
                    'message_id': data['id'],
                    'to_jid': data.get('to', ''),
                    'from_jid': data['from'],
                    'content': json.dumps(data.get('message', {})),
                    'message_type': data.get('type', 'text'),
                    'status': 'received',
                    'timestamp': data.get('t', int(time.time())),
                    'metadata': {
                        'is_group': data.get('isGroup', False),
                        'participant': data.get('participant')
                    }
                }
                await self._store_message(message)
            # Extract message data
            message = {
                'id': data.get('id'),
                'from': data.get('from'),
                'to': data.get('to'),
                'timestamp': data.get('t'),
                'type': data.get('type'),
                'notify': data.get('notify'),
                'is_group': data.get('isGroup', False),
                'is_forwarded': data.get('isForwarded', False),
                'is_ephemeral': data.get('isEphemeral', False),
                'is_status': data.get('isStatus', False),
                'message': data.get('message')
            }

            # Dispatch the message event
            await self._dispatch_event('message', message)

            # Handle message content based on type
            if 'message' in data and isinstance(data['message'], dict):
                msg_content = data['message']
                content_type = next(iter(msg_content.keys())) if msg_content else None

                if content_type == 'conversation':
                    await self._handle_text_message(message, msg_content[content_type])
                elif content_type == 'extendedTextMessage':
                    await self._handle_extended_text_message(message, msg_content[content_type])
                elif content_type == 'imageMessage':
                    await self._handle_image_message(message, msg_content[content_type])
                elif content_type == 'locationMessage':
                    await self._handle_location_message(message, msg_content[content_type])
                elif content_type == 'liveLocationMessage':
                    await self._handle_location_message(message, msg_content[content_type])
                elif content_type == 'protocolMessage' and msg_content[content_type].get('type') == 14:
                    # Handle live location notifications (updates/stops)
                    await self._handle_live_location_notification(msg_content[content_type])
                elif content_type == 'contactMessage':
                    # Handle contact sharing
                    await self._handle_contact_message(message, msg_content[content_type])
                elif content_type == 'contactsArrayMessage':
                    # Handle multiple contacts sharing
                    await self._handle_contacts_array_message(message, msg_content[content_type])

        except Exception as e:
            logger.error(f"Error handling message notification: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'message_handling'})

    async def _handle_text_message(self, message: Dict[str, Any], content: str):
        """Handle a simple text message."""
        try:
            message['content'] = content
            message['message_type'] = 'text'
            await self._dispatch_event('text_message', message)
        except Exception as e:
            logger.error(f"Error handling text message: {e}", exc_info=True)

    async def _handle_extended_text_message(self, message: Dict[str, Any], content: Dict[str, Any]):
        """Handle an extended text message (with context info, etc.)."""
        try:
            message.update({
                'content': content.get('text'),
                'context_info': content.get('contextInfo', {}),
                'message_type': 'extended_text',
            })
            await self._dispatch_event('extended_text_message', message)
        except Exception as e:
            logger.error(f"Error handling extended text message: {e}", exc_info=True)

    async def _handle_image_message(self, message: Dict[str, Any], content: Dict[str, Any]):
        """Handle an image message."""
        try:
            message.update({
                'media_key': content.get('mediaKey'),
                'mimetype': content.get('mimetype'),
                'caption': content.get('caption'),
                'file_sha256': content.get('fileSha256'),
                'file_length': content.get('fileLength'),
                'height': content.get('height'),
                'width': content.get('width'),
                'message_type': 'image',
            })
            await self._dispatch_event('image_message', message)
        except Exception as e:
            logger.error(f"Error handling image message: {e}", exc_info=True)

    async def _handle_contact_message(self, message: Dict[str, Any], content: Dict[str, Any]):
        """
        Handle a contact message.

        Args:
            message: The base message data
            content: The contact data from the message
        """
        try:
            contact = {
                'display_name': content.get('displayName'),
                'vcard': content.get('vcard'),
                'contact_id': content.get('contactId'),
                'contact_name': content.get('name'),
                'contact_number': content.get('number'),
            }

            message.update({
                'contact': contact,
                'message_type': 'contact',
            })

            await self._dispatch_event('contact_message', message)
        except Exception as e:
            logger.error(f"Error handling contact message: {e}", exc_info=True)

    async def _handle_contacts_array_message(self, message: Dict[str, Any], content: Dict[str, Any]):
        """
        Handle a contacts array message (multiple contacts).

        Args:
            message: The base message data
            content: The contacts data from the message
        """
        try:
            contacts = []
            for contact_data in content.get('contacts', []):
                contact = {
                    'display_name': contact_data.get('displayName'),
                    'vcard': contact_data.get('vcard'),
                    'contact_id': contact_data.get('contactId'),
                    'contact_name': contact_data.get('name'),
                    'contact_number': contact_data.get('number'),
                }
                contacts.append(contact)

            message.update({
                'contacts': contacts,
                'message_type': 'contacts_array',
            })

            await self._dispatch_event('contacts_array_message', message)
        except Exception as e:
            logger.error(f"Error handling contacts array message: {e}", exc_info=True)

    async def _handle_location_message(self, message: Dict[str, Any], content: Dict[str, Any]):
        """
        Handle a location message.

        Args:
            message: The base message data
            content: The location data from the message
        """
        try:
            # Parse location data
            location = {
                'latitude': float(content.get('degreesLatitude', 0)),
                'longitude': float(content.get('degreesLongitude', 0)),
                'name': content.get('name'),
                'address': content.get('address'),
                'url': content.get('url'),
                'is_live': content.get('isLive', False),
                'message_type': 'location',
            }

            # Add optional fields if present
            for field in ['accuracyInMeters', 'speedInMps', 'degreesClockwiseFromMagneticNorth']:
                if field in content:
                    location[field] = float(content[field])

            # Handle live location specific fields
            if location['is_live']:
                location.update({
                    'live_until': int(content.get('expiration', 0)) / 1000,  # Convert to seconds
                    'sequence_number': int(content.get('sequenceNumber', 0)),
                })

                # Track live location senders
                sender_key = f"{message.get('from')}:{message.get('participant', '')}"
                if not hasattr(self, '_tracked_live_locations'):
                    self._tracked_live_locations = {}

                # Store or update the live location
                self._tracked_live_locations[sender_key] = {
                    'message_id': message.get('id'),
                    'from': message.get('from'),
                    'participant': message.get('participant'),
                    'timestamp': int(message.get('t', time.time() * 1000)),
                    'location': location,
                    'last_update': time.time(),
                }

                # Dispatch live location update event
                await self._dispatch_event('live_location_update', {
                    'message_id': message.get('id'),
                    'from': message.get('from'),
                    'participant': message.get('participant'),
                    'timestamp': int(message.get('t', time.time() * 1000)),
                    'location': location,
                    'is_final': False,
                })

            # Dispatch regular location message event
            message.update({
                'location': location,
                'message_type': 'location',
            })
            await self._dispatch_event('location_message', message)

        except Exception as e:
            logger.error(f"Error handling location message: {e}", exc_info=True)
            await self._dispatch_event('error', {
                'error': str(e),
                'type': 'location_message_handling',
                'message': message,
                'content': content
            })

    async def _handle_live_location_notification(self, data: Dict[str, Any]):
        """
        Handle a live location notification (update or stop).

        Args:
            data: The notification data
        """
        try:
            if not hasattr(self, '_tracked_live_locations'):
                self._tracked_live_locations = {}

            sender_key = f"{data.get('from')}:{data.get('participant', '')}"

            # Check if this is a stop notification
            if data.get('type') == 'livelocation' and data.get('subtype') == 'stop':
                if sender_key in self._tracked_live_locations:
                    # Get the last known location
                    last_location = self._tracked_live_locations[sender_key]
                    # Dispatch final update
                    await self._dispatch_event('live_location_update', {
                        'message_id': last_location['message_id'],
                        'from': data.get('from'),
                        'participant': data.get('participant'),
                        'timestamp': int(time.time() * 1000),
                        'location': last_location['location'],
                        'is_final': True,
                    })
                    # Remove from tracking
                    del self._tracked_live_locations[sender_key]
                return

            # Handle location update
            location_data = data.get('location', {})
            if not location_data:
                return

            # Update tracked location
            if sender_key in self._tracked_live_locations:
                last_location = self._tracked_live_locations[sender_key]
                last_location['location'].update({
                    'latitude': float(location_data.get('degreesLatitude', 0)),
                    'longitude': float(location_data.get('degreesLongitude', 0)),
                    'last_update': time.time(),
                })

                # Add/update optional fields
                for field in ['accuracyInMeters', 'speedInMps', 'degreesClockwiseFromMagneticNorth']:
                    if field in location_data:
                        last_location['location'][field] = float(location_data[field])

                # Dispatch update event
                await self._dispatch_event('live_location_update', {
                    'message_id': last_location['message_id'],
                    'from': data.get('from'),
                    'participant': data.get('participant'),
                    'timestamp': int(data.get('t', time.time() * 1000)),
                    'location': last_location['location'],
                    'is_final': False,
                })

        except Exception as e:
            logger.error(f"Error handling live location notification: {e}", exc_info=True)
            await self._dispatch_event('error', {
                'error': str(e),
                'type': 'live_location_notification',
                'data': data
            })

    async def _handle_presence_update(self, data: Dict[str, Any]):
        """Handle a presence update."""
        try:
            presence = {
                'id': data.get('id'),
                'type': data.get('type'),
                't': data.get('t'),
                'participant': data.get('participant'),
                'is_online': data.get('isOnline', False),
                'last_seen': data.get('lastSeen'),
                'deny_cas_share': data.get('denyCasShare', False),
            }
            await self._dispatch_event('presence', presence)
        except Exception as e:
            logger.error(f"Error handling presence update: {e}", exc_info=True)

    async def _handle_chat_update(self, data: Dict[str, Any]):
        """Handle a chat update (e.g., read receipts, typing indicators)."""
        try:
            update_type = data.get('subtype')
            if update_type == 'read' and 'read_messages' in data:
                # Read receipt
                receipt = {
                    'id': data.get('id'),
                    'participant': data.get('participant'),
                    'read_messages': data['read_messages'],
                    'timestamp': data.get('t'),
                    'type': 'read_receipt',
                }
                await self._dispatch_event('read_receipt', receipt)
            elif update_type == 'typing' and 'is_typing' in data:
                # Typing indicator
                typing = {
                    'id': data.get('id'),
                    'participant': data.get('participant'),
                    'is_typing': data['is_typing'],
                    'type': 'typing',
                }
                await self._dispatch_event('typing', typing)
            else:
                # Forward other chat updates
                await self._dispatch_event('chat_update', data)
        except Exception as e:
            logger.error(f"Error handling chat update: {e}", exc_info=True)

    async def _handle_call_notification(self, data: Dict[str, Any]):
        """Handle a call notification."""
        try:
            call = {
                'id': data.get('id'),
                'from': data.get('from'),
                'status': data.get('status'),
                'is_video': data.get('isVideo', False),
                'offer_time': data.get('offerTime'),
                'duration': data.get('duration'),
                'type': 'call',
            }
            await self._dispatch_event('call', call)
        except Exception as e:
            logger.error(f"Error handling call notification: {e}", exc_info=True)

    async def _handle_contacts_update(self, data: Dict[str, Any]):
        """Handle a contacts update."""
        try:
            contacts = data.get('contacts', [])
            await self._dispatch_event('contacts_update', {'contacts': contacts})
        except Exception as e:
            logger.error(f"Error handling contacts update: {e}", exc_info=True)

    async def _handle_server_message(self, tag: int, payload: bytes):
        """
        Handle a message from the server.

        Args:
            tag: Message tag
            payload: Message payload
        """
        try:
            # Try to decode as a protocol node
            try:
                from .protocol import ProtocolDecoder
                decoder = ProtocolDecoder() # Updated: No keys passed
                node = decoder.decode(payload)
                await self._handle_protocol_node(node)
                return
            except Exception as e:
                logger.debug(f"Failed to decode as protocol node: {e}")

            # Try to decode as JSON
            try:
                json_data = json.loads(payload.decode('utf-8', errors='replace'))
                await self._process_json_message(json_data)
                return
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

            # Fall back to raw binary handler
            await self._handle_binary_message(payload)

        except Exception as e:
            logger.error(f"Error handling server message: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'server_message'})

    async def _handle_protocol_node(self, node):
        """
        Handle a protocol node from the server.

        Args:
            node: The protocol node to handle
        """
        try:
            # Log the node for debugging
            logger.debug(f"Received protocol node: {node}")
            
            # Handle receipt nodes (read, delivered, played)
            if node.tag in ('read', 'delivered', 'played'):
                await self._handle_receipt(node)
                return
                
            # Check for history sync notification in message nodes
            if node.tag == 'message':
                # Attempt to parse as a Protobuf message first
                message_obj = await self._parse_message_node(node)
                if message_obj:
                    await self._dispatch_event('message', message_obj)
                # If _parse_message_node returns None (e.g. not a protobuf message or parse error),
                # it might be an older style XML message or a special notification.
                # The original _handle_message_node logic might need to be called here for those cases,
                # or parts of it integrated if they handle non-protobuf message structures.
                # For now, as per instructions, we only dispatch if message_obj is not None.
                # The original logic for history sync notification inside 'message' type is now implicitly
                # handled if it's part of the protobuf payload, or needs to be re-evaluated if it's a distinct XML structure.
                # Based on the problem description, the focus is on protobuf messages.
                # The original _handle_message_node call is removed and replaced by _parse_message_node + dispatch.
                # History sync notification check:
                elif node.attrs.get('type') == 'notification' and node.get_child('sync'):
                    sync_node = node.get_child('sync')
                    if sync_node and sync_node.data: # Assuming sync_node.data is JSON string
                        try:
                            sync_data = json.loads(sync_node.data) # If sync_node.data is bytes, decode first
                            if 'history_sync' in sync_data:
                                await self._handle_history_sync(sync_data['history_sync'])
                                return
                        except (json.JSONDecodeError, KeyError) as e:
                             logger.error(f"Failed to parse history sync data: {e}")
                    # else:
                    #     logger.warning(f"Received non-protobuf message node, and not a known XML notification type: {node.tag}")

            elif node.tag == 'presence':
                await self._handle_presence_node(node)

            elif node.tag == 'iq':
                await self._handle_iq_node(node)

            elif node.tag == 'notification':
                # Handle other types of notifications
                notification_type = node.attrs.get('type')
                logger.debug(f"Received notification of type: {notification_type}")
                await self._dispatch_event('notification', {
                    'type': notification_type,
                    'from': node.attrs.get('from'),
                    'id': node.attrs.get('id'),
                    'data': node.to_dict() if hasattr(node, 'to_dict') else str(node)
                })

            else:
                logger.debug(f"Unhandled protocol node type: {node.tag}")
                await self._dispatch_event('protocol_node', {'node': node})

        except Exception as e:
            logger.error(f"Error handling protocol node: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'protocol_node'})

    async def _send_message_node(
        self,
        to: str,
        content_node: ProtocolNode,
        message_type: str = 'text',
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False
    ) -> str:
        """
        Send a message node to the specified recipient.

        Args:
            to: Recipient JID
            content_node: The protocol node containing the message content
            message_type: Type of the message (text, contact, contacts_array, etc.)

        Returns:
            The message ID of the sent message

        Raises:
            PymeowError: If there's an error sending the message
        """
        try:
            # Generate a unique message ID
            message_id = self._generate_message_id()

            # Get current timestamp
            timestamp = int(time.time() * 1000)

            # Create the message node with basic attributes
            message_node = ProtocolNode(
                tag='message',
                attrs={
                    'id': message_id,
                    'type': 'text',
                    'to': to,
                    't': str(timestamp)
                },
                content=[content_node]
            )

            # Apply disappearing message settings if needed
            try:
                if expiration_seconds is not None or is_ephemeral:
                    self._disappearing_messages.update_message_node(
                        message_node=message_node,
                        expiration_seconds=expiration_seconds,
                        is_ephemeral=is_ephemeral
                    )
            except DisappearingMessageError as e:
                logger.warning(f"Failed to apply disappearing message settings: {e}")
                # Continue without disappearing settings rather than failing the message send

            # Add message type attribute if provided
            if message_type and message_type != 'text':
                message_node.attrs['type'] = message_type

            # Add to pending messages
            future = asyncio.Future()
            self._pending_messages[message_id] = future

            result = None
            try:
                # Send the message
                await self._enqueue_message(message_node)

                # Wait for the message to be sent with a timeout
                try:
                    await asyncio.wait_for(future, timeout=30.0)
                    result = message_id
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout waiting for message {message_id} to be sent")
                    result = message_id
                return result

            except Exception as e:
                logger.error(f"Error sending message node: {e}", exc_info=True)
                raise PymeowError(f"Failed to send message: {e}") from e

            finally:
                # Clean up the pending message
                if message_id in self._pending_messages:
                    del self._pending_messages[message_id]

        except Exception as e:
            error_msg = f"Failed to prepare message node: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def _parse_message_node(self, node: ProtocolNode) -> Optional[Message]:
        """
        Parse a message protocol node into a WAWebProtobufsE2E_pb2.Message object.

        Args:
            node: The protocol node to parse

        Returns:
            A WAWebProtobufsE2E_pb2.Message object or None if parsing fails.
        """
        if not node or not hasattr(node, 'attrs'):
            logger.warning("Attempted to parse an invalid or empty node.")
            return None

        # Extract stanza info
        node_attrs_id = node.attrs.get('id')
        from_jid_str = node.attrs.get('from')
        to_jid_str = node.attrs.get('to')
        participant_jid_str = node.attrs.get('participant')
        timestamp_str = node.attrs.get('t')
        # node_type = node.attrs.get('type') # This is XML type, protobuf message has its own type fields

        if not isinstance(node.content, bytes) or not node.content:
            # This might be an older XML-formatted message or a notification without a protobuf body.
            # For this refactoring, we are focusing on messages with Protobuf content.
            # logger.debug(f"Message node {node_attrs_id} has no binary content to parse into Protobuf Message. XML type: {node_type}")
            return None

        try:
            parsed_proto_msg = WAWebProtobufsE2E_pb2.Message()
            parsed_proto_msg.ParseFromString(node.content)
        except Exception as e:
            logger.error(f"Failed to parse Protobuf content for message {node_attrs_id}: {e}", exc_info=True)
            return None

        # Populate/Override key and timestamp from stanza attributes
        # The key is of type WACommon_pb2.MessageKey, which is already the type of parsed_proto_msg.key
        if node_attrs_id:
            parsed_proto_msg.key.id = node_attrs_id
        
        is_from_me = False
        if self._auth_state and self._auth_state.device and hasattr(self._auth_state.device, 'id_str'):
            is_from_me = (from_jid_str == self._auth_state.device.id_str)
        elif self._auth_state and self._auth_state.me: # Fallback if device.id_str is not available
             is_from_me = (from_jid_str == str(self._auth_state.me))


        parsed_proto_msg.key.from_me = is_from_me

        if is_from_me:
            if to_jid_str:
                parsed_proto_msg.key.remote_jid = to_jid_str
        else:
            if from_jid_str:
                parsed_proto_msg.key.remote_jid = from_jid_str
        
        if participant_jid_str:
            parsed_proto_msg.key.participant = participant_jid_str
        
        if timestamp_str:
            try:
                parsed_proto_msg.message_timestamp = int(timestamp_str)
            except ValueError:
                logger.warning(f"Invalid timestamp format for message {node_attrs_id}: {timestamp_str}")
        
        return parsed_proto_msg

    # _handle_message_node is effectively replaced by the logic in _handle_protocol_node
    # that now calls _parse_message_node and dispatches the protobuf object.

    async def _handle_presence_node(self, node):
        """Handle a presence protocol node.

        This method handles both user presence updates and chat state (typing) notifications.
        It dispatches appropriate events for each type of presence update.
        """
        try:
            # First check if this is a chat state (typing) notification
            if node.attrs.get('type') == 'composing' or node.attrs.get('type') == 'paused':
                # This is a chat state (typing) notification
                from_jid = node.attrs.get('from', '')
                to_jid = node.attrs.get('to', '')
                state = ChatPresence.COMPOSING if node.attrs.get('type') == 'composing' else ChatPresence.PAUSED

                # Get media type if present
                media = ChatPresenceMedia.TEXT
                media_attr = node.attrs.get('media')
                if media_attr:
                    try:
                        media = ChatPresenceMedia(media_attr)
                    except ValueError:
                        logger.warning(f"Unknown chat presence media: {media_attr}")

                # Dispatch chat presence event
                event = ChatPresenceEvent(
                    from_jid=from_jid,
                    to_jid=to_jid,
                    state=state,
                    media=media
                )
                await self._dispatch_event('chat_presence', event)
            else:
                # Regular presence update
                from_jid = node.attrs.get('from', '')
                presence_type = node.attrs.get('type')

                event = PresenceEvent(
                    from_jid=from_jid,
                    unavailable=(presence_type == 'unavailable'),
                )

                # Handle last seen timestamp if available
                last_seen = node.attrs.get('last')
                if last_seen and last_seen != 'deny':
                    try:
                        from datetime import datetime
                        event.last_seen = datetime.fromtimestamp(int(last_seen))
                    except (TypeError, ValueError) as e:
                        logger.warning(f"Invalid last seen timestamp {last_seen}: {e}")

                await self._dispatch_event('presence', event)

                # Also dispatch the raw node for backward compatibility
                await self._dispatch_event('presence_raw', {
                    'from': from_jid,
                    'to': node.attrs.get('to'),
                    'type': presence_type,
                    'last': last_seen,
                    'node': node
                })

        except Exception as e:
            logger.error(f"Error handling presence node: {e}", exc_info=True)

    async def _handle_iq_node(self, node):
        """Handle an IQ (Info/Query) protocol node."""
        try:
            iq = {
                'id': node.attrs.get('id'),
                'type': node.attrs.get('type'),
                'to': node.attrs.get('to'),
                'from': node.attrs.get('from'),
                'xmlns': node.attrs.get('xmlns'),
                'node': node  # Include the raw node
            }
            await self._dispatch_event('iq', iq)
        except Exception as e:
            logger.error(f"Error handling IQ node: {e}", exc_info=True)

    async def _handle_binary_data(self, data: bytes, msg_tag: Optional[str] = None) -> None:
        """
        Handle binary data received from the WebSocket connection.

        This method processes different types of binary data including media messages,
        documents, and other binary attachments.

        Args:
            data: The binary data to process
            msg_tag: Optional message tag for tracking responses

        The binary data format is expected to be:
        - First byte: Message type/format
        - Next 4 bytes: Message length (big endian)
        - Remaining bytes: Message payload
        """
        if not data:
            logger.warning("Received empty binary data")
            return

        try:
            logger.debug(f"Processing binary data: {len(data)} bytes, tag: {msg_tag}")

            # Extract message type and length from the header if present
            if len(data) >= 5:
                msg_type = data[0]
                msg_length = int.from_bytes(data[1:5], 'big')
                payload = data[5:5+msg_length] if msg_length > 0 else b''

                # Log the message type for debugging
                msg_type_name = {
                    0x01: 'MEDIA',
                    0x02: 'DOCUMENT',
                    0x03: 'AUDIO',
                    0x04: 'STICKER',
                    0x05: 'VIDEO',
                    0x06: 'ANIMATION',
                }.get(msg_type, f'UNKNOWN(0x{msg_type:02x})')

                logger.debug(f"Binary message type: {msg_type_name}, length: {msg_length}")

                # Handle different message types
                if msg_type == 0x01:  # Media message
                    await self._handle_media_data(payload, msg_tag)
                elif msg_type == 0x02:  # Document
                    await self._handle_document_data(payload, msg_tag)
                elif msg_type in (0x03, 0x04, 0x05, 0x06):  # Audio, Sticker, Video, Animation
                    await self._handle_media_data(payload, msg_tag, msg_type=msg_type)
                else:
                    logger.warning(f"Unhandled binary message type: 0x{msg_type:02x}")
                    await self._dispatch_event('binary_message', {
                        'type': 'unknown',
                        'data': data,
                        'tag': msg_tag
                    })
            else:
                # Handle raw binary data without header
                logger.debug("Received raw binary data without header")
                await self._dispatch_event('binary_message', {
                    'type': 'raw',
                    'data': data,
                    'tag': msg_tag
                })

        except Exception as e:
            error_msg = f"Error handling binary data: {e}"
            logger.error(error_msg, exc_info=True)
            await self._dispatch_event('error', {
                'error': error_msg,
                'type': 'binary_data_processing',
                'tag': msg_tag
            })

    async def _handle_media_data(self, data: bytes, msg_tag: Optional[str] = None, msg_type: int = 0x01) -> None:
        """
        Handle binary media data (images, videos, audio, etc.).

        Args:
            data: The media data
            msg_tag: Optional message tag
            msg_type: Type of media (default: 0x01 for image)
        """
        try:
            media_type_map = {
                0x01: 'image',
                0x03: 'audio',
                0x04: 'sticker',
                0x05: 'video',
                0x06: 'animation',
            }

            media_type = media_type_map.get(msg_type, 'unknown')
            logger.debug(f"Handling {media_type} media data: {len(data)} bytes")

            # Generate a unique filename
            import hashlib
            import os
            from datetime import datetime

            # Create media directory if it doesn't exist
            media_dir = os.path.join(str(self._data_dir), 'media')
            os.makedirs(media_dir, exist_ok=True)

            # Generate a filename with timestamp and hash
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_hash = hashlib.sha256(data).hexdigest()[:8]
            extension = self._get_media_extension(data, media_type)
            filename = f"{timestamp}_{file_hash}.{extension}"
            filepath = os.path.join(media_dir, filename)

            # Save the media file
            with open(filepath, 'wb') as f:
                f.write(data)

            logger.info(f"Saved {media_type} to {filepath}")

            # Dispatch event with file information
            await self._dispatch_event('media_message', {
                'type': media_type,
                'file_path': filepath,
                'file_size': len(data),
                'file_name': filename,
                'mime_type': self._get_mime_type(extension),
                'tag': msg_tag
            })

        except Exception as e:
            logger.error(f"Error handling media data: {e}", exc_info=True)
            await self._dispatch_event('error', {
                'error': f"Failed to process media: {e}",
                'type': 'media_processing',
                'tag': msg_tag
            })

    async def _handle_document_data(self, data: bytes, msg_tag: Optional[str] = None) -> None:
        """
        Handle binary document data.

        Args:
            data: The document data
            msg_tag: Optional message tag
        """
        try:
            logger.debug(f"Handling document data: {len(data)} bytes")

            # Generate a unique filename
            import hashlib
            import os
            from datetime import datetime

            # Create documents directory if it doesn't exist
            docs_dir = os.path.join(str(self._data_dir), 'documents')
            os.makedirs(docs_dir, exist_ok=True)

            # Try to determine file type from content
            extension = self._detect_document_type(data)

            # Generate filename with timestamp and hash
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_hash = hashlib.sha256(data).hexdigest()[:8]
            filename = f"doc_{timestamp}_{file_hash}.{extension}"
            filepath = os.path.join(docs_dir, filename)

            # Save the document
            with open(filepath, 'wb') as f:
                f.write(data)

            logger.info(f"Saved document to {filepath}")

            # Dispatch event with document information
            await self._dispatch_event('document_message', {
                'file_path': filepath,
                'file_name': filename,
                'file_size': len(data),
                'mime_type': self._get_mime_type(extension),
                'tag': msg_tag
            })

        except Exception as e:
            logger.error(f"Error handling document data: {e}", exc_info=True)
            await self._dispatch_event('error', {
                'error': f"Failed to process document: {e}",
                'type': 'document_processing',
                'tag': msg_tag
            })

    async def _handle_binary_message(self, data: bytes):
        """
        Handle a raw binary message that couldn't be decoded as a protocol node or JSON.

        Args:
            data: The raw binary data
        """
        try:
            logger.debug(f"Received binary message: {data.hex()}")
            # Forward to the binary data handler
            await self._handle_binary_data(data)
        except Exception as e:
            logger.error(f"Error handling binary message: {e}", exc_info=True)
            await self._dispatch_event('error', {'error': str(e), 'type': 'binary_message'})

    def _generate_message_id_suffix(self) -> str:
        """
        Generate a random suffix for message IDs.

        Returns:
            A random 8-character hexadecimal string
        """
        import random
        import string
        return ''.join(random.choices(string.hexdigits.upper()[:16], k=8))

    def _generate_id(self) -> str:
        """
        Generate a unique ID for operations.

        Returns:
            A unique ID string
        """
        import time
        import random
        import string

        timestamp = int(time.time() * 1000)
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f'{timestamp}-{random_suffix}'

    def _generate_message_id(self) -> str:
        """
        Generate a unique message ID.

        Returns:
            A unique message ID string
        """
        import time
        timestamp = int(time.time() * 1000)
        return f'{self._auth_state.device.device_id.upper()}{timestamp}-{self._generate_message_id_suffix()}'

    def _get_media_extension(self, data: bytes, media_type: str) -> str:
        """
        Determine the file extension based on the media type and content.

        Args:
            data: The media data
            media_type: Type of media (e.g., 'image', 'video')

        Returns:
            File extension (without dot)
        """
        # Default extensions based on media type
        default_extensions = {
            'image': 'jpg',
            'video': 'mp4',
            'audio': 'mp3',
            'sticker': 'webp',
            'animation': 'gif'
        }

        # Try to determine the actual file type from the magic bytes
        if len(data) >= 4:
            magic = data[:4].hex().upper()

            # Common file signatures
            signatures = {
                'FFD8FF': 'jpg',
                '89504E47': 'png',
                '47494638': 'gif',
                '52494646': 'webp',  # 'RIFF' followed by 'WEBP'
                '66747970': 'mp4',   # 'ftyp' for MP4
                '1A45DFA3': 'webm',  # WebM/Matroska
                '4F676753': 'ogg',    # Ogg
                '494433': 'mp3',      # ID3 tag
                'FFFB': 'mp3',        # MP3 without ID3 tag
            }

            # Check for WebP specifically (RIFF followed by WEBP)
            if magic.startswith('52494646') and len(data) > 12 and data[8:12] == b'WEBP':
                return 'webp'

            # Check other signatures
            for sig, ext in signatures.items():
                if magic.startswith(sig):
                    return ext

        # Fall back to default extension for the media type
        return default_extensions.get(media_type, 'bin')

    def _get_mime_type(self, extension: str) -> str:
        """
        Get the MIME type for a file extension.

        Args:
            extension: File extension (without dot)

        Returns:
            MIME type string
        """
        mime_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'mp4': 'video/mp4',
            'mp3': 'audio/mpeg',
            'ogg': 'audio/ogg',
            'webm': 'video/webm',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            '7z': 'application/x-7z-compressed',
            'gz': 'application/gzip',
            'tar': 'application/x-tar',
            'txt': 'text/plain',
            'rtf': 'application/rtf',
            'json': 'application/json',
            'xml': 'application/xml',
            'csv': 'text/csv',
            'bin': 'application/octet-stream'
        }
        return mime_types.get(extension.lower(), 'application/octet-stream')

    def _detect_document_type(self, data: bytes) -> str:
        """
        Detect the document type from binary data.

        Args:
            data: The document data

        Returns:
            File extension (without dot)
        """
        if len(data) < 4:
            return 'bin'

        magic = data[:8].hex().upper()

        # Common document signatures
        signatures = {
            '25504446': 'pdf',       # PDF
            '504B0304': 'docx',      # ZIP-based formats (docx, xlsx, pptx)
            'D0CF11E0A1B11AE1': 'doc',  # Old MS Office (doc, xls, ppt)
            '504B0506': 'zip',       # ZIP archive
            '52617221': 'rar',       # RAR archive
            '1F8B08': 'gz',          # GZIP
            '377ABCAF271C': '7z',    # 7-Zip
            '7B5C7274': 'rtf',       # RTF
            '3C3F786D6C': 'xml',     # XML
            'EFBBBF3C3F': 'xml',     # UTF-8 BOM + XML
            '00010000': 'ttf',       # TrueType font
            '4F676753': 'ogg',       # OGG
            '3026B2758E66CF11': 'wmv',  # WMV
            '2E524D46': 'rm',        # RealMedia
            '4D546864': 'mid',       # MIDI
            '1A45DFA3': 'mkv',       # Matroska
            '000001BA': 'mpg',       # MPEG
        }

        # Check signatures
        for sig, ext in signatures.items():
            if magic.startswith(sig):
                return ext

        # Check for text files
        try:
            text = data[:1024].decode('utf-8', errors='ignore')
            if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in text):
                return 'txt'
        except:
            pass

        return 'bin'  # Default to binary if unknown

    def _generate_thumbnail(self, file_path: str, output_size: tuple[int, int] = (100, 100)) -> Optional[bytes]:
        """
        Generate a thumbnail for an image or video file.

        Args:
            file_path: Path to the media file
            output_size: Size of the thumbnail (width, height)

        Returns:
            Thumbnail data as bytes, or None if generation fails
        """
        try:
            img = Image.open(file_path)

            # Convert to RGB if necessary (for PNG with transparency)
            if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[-1])
                img = background

            # Create thumbnail
            img.thumbnail(output_size)

            # Convert to JPEG
            output = io.BytesIO()
            img.convert('RGB').save(output, format='JPEG', quality=85)
            return output.getvalue()

        except Exception as e:
            logger.warning(f"Failed to generate thumbnail for {file_path}: {e}")
            return None

    async def send_media(
        self,
        to: str,
        file_path: str,
        message_type: str = 'image',
        caption: Optional[str] = None,
        mime_type: Optional[str] = None,
        thumbnail: Optional[bytes] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Send a media file (image, video, audio, document) to a chat.

        Args:
            to: Recipient JID
            file_path: Path to the media file
            message_type: Type of media ('image', 'video', 'audio', 'document')
            caption: Optional caption for the media
            mime_type: MIME type of the file (auto-detected if not provided)
            thumbnail: Optional thumbnail data (auto-generated if not provided for images/videos)
            progress_callback: Optional callback for upload progress (uploaded_bytes, total_bytes)

        Returns:
            Message ID of the sent message

        Raises:
            FileNotFoundError: If the media file doesn't exist
            PymeowError: If there's an error sending the media
        """
        # Check if file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Media file not found: {file_path}")

        # Get file info
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Determine MIME type if not provided
        if mime_type is None:
            mime_guess = mimetypes.guess_type(file_path)[0]
            mime_type = mime_guess or 'application/octet-stream'

        # Generate thumbnail for images/videos if not provided
        if thumbnail is None and message_type in ('image', 'video'):
            thumbnail = self._generate_thumbnail(file_path)

        # Read file in chunks for progress tracking
        async def file_chunk_generator():
            with open(file_path, 'rb') as f:
                chunk_size = 65536  # 64KB chunks
                total_read = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    total_read += len(chunk)
                    if progress_callback:
                        progress_callback(total_read, file_size)

                    yield chunk

        # Upload media to WhatsApp servers
        try:
            # This is a placeholder for the actual media upload logic
            # In a real implementation, you would upload the media to WhatsApp's servers
            # and get a media key and URL
            media_key = os.urandom(32).hex()

            # Create media info node
            media_info = {
                'type': message_type,
                'url': f'https://mmg.whatsapp.net/d/f/{media_key}/{file_name}',
                'mimetype': mime_type,
                'file_sha256': await self._calculate_file_hash(file_path),
                'file_length': file_size,
                'media_key': media_key,
                'media_key_timestamp': str(int(time.time())),
                'file_name': file_name,
            }

            # Add thumbnail if available
            if thumbnail:
                media_info['jpeg_thumbnail'] = base64.b64encode(thumbnail).decode('ascii')

            # Add caption if provided
            if caption:
                media_info['caption'] = caption

            # Create message node
            message_id = self._generate_message_id()
            message_node = {
                'tag': 'message',
                'attrs': {
                    'to': to,
                    'type': 'media',
                    'id': message_id,
                },
                'content': [
                    {'tag': 'media', 'attrs': media_info}
                ]
            }

            # Convert to ProtocolNode and send
            node = ProtocolNode.from_dict(message_node)
            await self._send_node(node)

            # Log the sent media
            logger.info(f"Sent {message_type} to {to}: {file_name} ({file_size} bytes)")

            return message_id

        except Exception as e:
            error_msg = f"Failed to send media: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate the SHA-256 hash of a file.

        Args:
            file_path: Path to the file

        Returns:
            Hex-encoded SHA-256 hash of the file
        """
        import hashlib

        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            # Read in 64KB chunks
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)

        return sha256.hexdigest()

    async def send_audio(
        self,
        to: str,
        audio_path: str,
        voice_note: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Send an audio message to a chat.

        Args:
            to: Recipient JID
            audio_path: Path to the audio file
            voice_note: If True, sends as a voice note (auto-plays in the chat)
            progress_callback: Optional callback for tracking upload progress

        Returns:
            The message ID of the sent audio

        Raises:
            PymeowError: If sending the audio fails
        """
        try:
            # Generate a unique message ID
            message_id = self._generate_message_id()

            # Get file info
            file_path = Path(audio_path)
            file_name = file_path.name
            file_size = file_path.stat().st_size

            # Detect MIME type if not provided
            mime_type = 'audio/mp4'  # Default MIME type
            if file_path.suffix.lower() == '.ogg':
                mime_type = 'audio/ogg; codecs=opus'
            elif file_path.suffix.lower() == '.mp3':
                mime_type = 'audio/mpeg'

            # Log the audio sending attempt
            logger.info(f"Sending audio to {to}: {file_name} ({file_size} bytes)")

            # Send the media using the generic media sender
            message_id = await self.send_media(
                to=to,
                file_path=audio_path,
                message_type='audio',
                mime_type=mime_type,
                progress_callback=progress_callback
            )

            # If it's a voice note, add the voice note flag
            if voice_note:
                await self._send_voice_note_metadata(message_id, to)

            # Log the sent audio
            log_msg = f"Sent {'voice note' if voice_note else 'audio'} to {to}: {file_name} ({file_size} bytes)"
            logger.info(log_msg)

            return message_id

        except Exception as e:
            error_msg = f"Failed to send audio: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def _send_voice_note_metadata(self, message_id: str, to: str) -> None:
        """
        Send metadata to mark a message as a voice note.

        Args:
            message_id: The ID of the message to mark as a voice note
            to: Recipient JID
        """
        try:
            # Create the voice note metadata node
            metadata_node = ProtocolNode(
                tag='enc',
                attrs={
                    'v': '2',
                    'type': 'ptt',
                    'mediatype': 'audio/ogg; codecs=opus'
                }
            )

            # Create the message node with the metadata
            message_node = ProtocolNode(
                tag='message',
                attrs={
                    'id': message_id,
                    'to': to,
                    'type': 'media',
                    'class': 'ptt'
                },
                content=[metadata_node]
            )

            # Send the metadata
            await self._send_node(message_node)

        except Exception as e:
            logger.error(f"Failed to send voice note metadata: {e}", exc_info=True)
            raise PymeowError(f"Failed to send voice note metadata: {e}") from e

    async def send_location(
        self,
        to: str,
        latitude: float,
        longitude: float,
        name: Optional[str] = None,
        address: Optional[str] = None,
        accuracy: Optional[int] = None,
        speed: Optional[float] = None,
        heading: Optional[int] = None,
    ) -> str:
        """
        Send a location message.

        Args:
            to: Recipient JID
            latitude: Latitude of the location
            longitude: Longitude of the location
            name: Optional name for the location
            address: Optional address for the location
            accuracy: Optional accuracy in meters
            speed: Optional speed in meters per second
            heading: Optional heading in degrees (0-360)

        Returns:
            The message ID of the sent location
        """
        try:
            # Create location message node
            location_node = ProtocolNode(
                tag='location',
                attrs={
                    'latitude': str(latitude),
                    'longitude': str(longitude),
                }
            )

            # Add optional fields
            if name:
                location_node.attrs['name'] = name
            if address:
                location_node.attrs['address'] = address
            if accuracy is not None:
                location_node.attrs['accuracy'] = str(int(accuracy))
            if speed is not None:
                location_node.attrs['speed'] = str(speed)
            if heading is not None:
                location_node.attrs['heading'] = str(heading)

            # Send the message
            return await self._send_message_node(to, location_node)

        except Exception as e:
            error_msg = f"Failed to send location: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def send_live_location(
        self,
        to: str,
        latitude: float,
        longitude: float,
        duration: int = 3600,  # Default 1 hour
        name: Optional[str] = None,
        address: Optional[str] = None,
        accuracy: Optional[int] = None,
        speed: Optional[float] = None,
        heading: Optional[int] = None,
    ) -> str:
        """
        Start sharing live location.

        Args:
            to: Recipient JID
            latitude: Initial latitude
            longitude: Initial longitude
            duration: Duration in seconds (default: 3600)
            name: Optional name for the location
            address: Optional address for the location
            accuracy: Optional accuracy in meters
            speed: Optional speed in meters per second
            heading: Optional heading in degrees (0-360)

        Returns:
            The message ID of the live location message
        """
        try:
            # Create live location node
            location_node = ProtocolNode(
                tag='livelocation',
                attrs={
                    'latitude': str(latitude),
                    'longitude': str(longitude),
                    'duration': str(duration * 1000),  # Convert to milliseconds
                    'is_live': 'true',
                }
            )

            # Add optional fields
            if name:
                location_node.attrs['name'] = name
            if address:
                location_node.attrs['address'] = address
            if accuracy is not None:
                location_node.attrs['accuracy'] = str(int(accuracy))
            if speed is not None:
                location_node.attrs['speed'] = str(speed)
            if heading is not None:
                location_node.attrs['heading'] = str(heading)

            # Send the message
            message_id = await self._send_message_node(to, location_node)

            # Store the live location session
            if not hasattr(self, '_live_locations'):
                self._live_locations = {}
            self._live_locations[message_id] = {
                'to': to,
                'start_time': time.time(),
                'end_time': time.time() + duration,
                'last_update': time.time(),
                'last_location': (latitude, longitude)
            }

            return message_id

        except Exception as e:
            error_msg = f"Failed to send live location: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def update_live_location(
        self,
        message_id: str,
        latitude: float,
        longitude: float,
        speed: Optional[float] = None,
        heading: Optional[int] = None,
        accuracy: Optional[int] = None
    ) -> bool:
        """
        Update an active live location.

        Args:
            message_id: The original live location message ID
            latitude: New latitude
            longitude: New longitude
            speed: Optional speed in meters per second
            heading: Optional heading in degrees (0-360)
            accuracy: Optional accuracy in meters

        Returns:
            bool: True if the update was successful
        """
        if not hasattr(self, '_live_locations') or message_id not in self._live_locations:
            raise PymeowError("No active live location session with the given message ID")

        session = self._live_locations[message_id]

        # Check if the session has expired
        if time.time() > session['end_time']:
            del self._live_locations[message_id]
            raise PymeowError("Live location session has expired")

        try:
            # Create update node
            update_node = ProtocolNode(
                tag='livelocation',
                attrs={
                    'v': '2',
                    'type': 'update',
                    'id': message_id,
                    't': str(int(time.time() * 1000)),
                    'latitude': str(latitude),
                    'longitude': str(longitude),
                }
            )

            # Add optional fields
            if speed is not None:
                update_node.attrs['speed'] = str(speed)
            if heading is not None:
                update_node.attrs['heading'] = str(heading)
            if accuracy is not None:
                update_node.attrs['accuracy'] = str(int(accuracy))

            # Send the update
            await self._send_node(update_node)

            # Update session
            session['last_update'] = time.time()
            session['last_location'] = (latitude, longitude)

            return True

        except Exception as e:
            error_msg = f"Failed to update live location: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def stop_live_location(self, message_id: str) -> bool:
        """
        Stop sharing live location.

        Args:
            message_id: The original live location message ID

        Returns:
            bool: True if the live location was stopped successfully
        """
        if not hasattr(self, '_live_locations') or message_id not in self._live_locations:
            raise PymeowError("No active live location session with the given message ID")

        session = self._live_locations[message_id]

        try:
            # Create stop node
            stop_node = ProtocolNode(
                tag='livelocation',
                attrs={
                    'v': '2',
                    'type': 'stop',
                    'id': message_id,
                    't': str(int(time.time() * 1000)),
                }
            )

            # Send the stop message
            await self._send_node(stop_node)

            # Remove the session
            del self._live_locations[message_id]

            return True

        except Exception as e:
            error_msg = f"Failed to stop live location: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def send_document(
        self,
        to: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        mime_type: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Send a document file to a chat.

        Args:
            to: Recipient JID
            file_path: Path to the document file
            caption: Optional caption for the document
            file_name: Custom file name (defaults to the original filename)
            mime_type: MIME type of the file (auto-detected if not provided)
            progress_callback: Optional callback for upload progress (uploaded_bytes, total_bytes)

        Returns:
            Message ID of the sent message

        Raises:
            FileNotFoundError: If the document file doesn't exist
            PymeowError: If there's an error sending the document
        """
        import os
        import mimetypes

        # Check if file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Document file not found: {file_path}")

        # Get file info
        original_file_name = os.path.basename(file_path)
        file_name = file_name or original_file_name
        file_size = os.path.getsize(file_path)

        # Determine MIME type if not provided
        if mime_type is None:
            mime_guess = mimetypes.guess_type(file_path)[0]
            mime_type = mime_guess or 'application/octet-stream'

        # Upload media to WhatsApp servers (using the media sending method)
        try:
            message_id = await self.send_media(
                to=to,
                file_path=file_path,
                message_type='document',
                caption=caption,
                mime_type=mime_type,
                progress_callback=progress_callback
            )

            # Log the sent document
            logger.info(f"Sent document to {to}: {file_name} ({file_size} bytes)")

            return message_id

        except Exception as e:
            error_msg = f"Failed to send document: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def send_image(
        self,
        to: str,
        image_path: str,
        caption: Optional[str] = None,
        view_once: bool = False,
        as_sticker: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Send an image to a chat.

        Args:
            to: Recipient JID
            image_path: Path to the image file
            caption: Optional caption for the image
            view_once: If True, sends as a view-once image (disappears after viewing)
            as_sticker: If True, sends the image as a sticker (without compression)
            progress_callback: Optional callback for upload progress (uploaded_bytes, total_bytes)

        Returns:
            Message ID of the sent message

        Raises:
            FileNotFoundError: If the image file doesn't exist
            PymeowError: If there's an error sending the image
        """
        from PIL import Image

        # Check if file exists
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")

        # Get image info
        file_name = os.path.basename(image_path)
        file_size = os.path.getsize(image_path)

        # Validate image format
        try:
            with Image.open(image_path) as img:
                width, height = img.size
                # Ensure the image is in a supported format
                if img.format.lower() not in ('jpeg', 'png', 'webp'):
                    logger.warning(f"Image format {img.format} might not be fully supported by WhatsApp")
        except Exception as e:
            logger.warning(f"Could not validate image: {e}")

        # Determine message type
        message_type = 'sticker' if as_sticker else 'image'

        # Upload and send the image
        try:
            message_id = await self.send_media(
                to=to,
                file_path=image_path,
                message_type=message_type,
                caption=caption,
                mime_type=f'image/{img.format.lower()}' if 'img' in locals() else 'image/jpeg',
                progress_callback=progress_callback
            )

            # Add view-once flag if needed
            if view_once and not as_sticker:  # View-once not supported for stickers
                await self._send_view_once_metadata(message_id, to)

            # Log the sent image
            log_msg = f"Sent {'sticker' if as_sticker else 'image'}{' (view once)' if view_once and not as_sticker else ''} to {to}: {file_name} ({file_size} bytes)"
            logger.info(log_msg)

            return message_id

        except Exception as e:
            error_msg = f"Failed to send image: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    async def _send_view_once_metadata(self, message_id: str, to: str) -> None:
        """
        Add view-once metadata to a message.

        Args:
            message_id: The ID of the message to modify
            to: Recipient JID
        """
        try:
            # Create a view-once message node
            view_once_node = {
                'tag': 'view_once',
                'attrs': {},
                'content': [
                    {
                        'tag': 'message',
                        'attrs': {
                            'from': f"{self._auth_state.phone_number}@s.whatsapp.net" if self._auth_state and self._auth_state.phone_number else "",
                            'to': to,
                            'id': message_id,
                            't': str(int(time.time()))
                        }
                    }
                ]
            }

            # Convert to ProtocolNode and send
            node = ProtocolNode.from_dict(view_once_node)
            await self._send_node(node)
            logger.debug(f"Added view-once metadata to message {message_id}")

        except Exception as e:
            logger.error(f"Failed to add view-once metadata to message {message_id}: {e}", exc_info=True)
            raise PymeowError(f"Failed to set view-once: {e}") from e

    async def send_video(
        self,
        to: str,
        video_path: str,
        caption: Optional[str] = None,
        gif: bool = False,
        view_once: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Send a video or GIF to a chat.

        Args:
            to: Recipient JID
            video_path: Path to the video file
            caption: Optional caption for the video
            gif: If True, sends as a GIF (looping video)
            view_once: If True, sends as a view-once video (disappears after viewing)
            progress_callback: Optional callback for upload progress (uploaded_bytes, total_bytes)

        Returns:
            Message ID of the sent message

        Raises:
            FileNotFoundError: If the video file doesn't exist
            PymeowError: If there's an error sending the video
        """
        # Check if file exists
        if not os.path.isfile(video_path):  # todo: use the Path object instead of os.path
            raise FileNotFoundError(f"Video file not found: {video_path}")

        # Get video info
        file_name = os.path.basename(video_path)
        file_size = os.path.getsize(video_path)

        # Determine MIME type based on file extension
        if gif:
            mime_type = 'video/mp4'  # WhatsApp expects GIFs as MP4
        else:
            mime_type = self._get_mime_type(file_name.split('.')[-1])
            if not mime_type.startswith('video/'):
                mime_type = 'video/mp4'  # Default to MP4 if unknown

        # Upload and send the video
        try:
            message_id = await self.send_media(
                to=to,
                file_path=video_path,
                message_type='video',
                caption=caption,
                mime_type=mime_type,
                progress_callback=progress_callback
            )

            # Add view-once flag if needed
            if view_once:
                await self._send_view_once_metadata(message_id, to)

            # Log the sent video
            log_msg = f"Sent {'GIF' if gif else 'video'}{' (view once)' if view_once else ''} to {to}: {file_name} ({file_size} bytes)"
            logger.info(log_msg)

            return message_id

        except Exception as e:
            error_msg = f"Failed to send {'GIF' if gif else 'video'}: {e}"
            logger.error(error_msg, exc_info=True)
            raise PymeowError(error_msg) from e

    def _get_video_dimensions(self, video_path: str) -> Tuple[Optional[int], Optional[int]]:
        """
        Get the dimensions of a video file.

        Args:
            video_path: Path to the video file

        Returns:
            Tuple of (width, height) or (None, None) if unknown
        """
        try:
            # Use ffprobe to get video dimensions
            cmd = [
                'ffprobe',
                '-v', 'error',
                '-select_streams', 'v:0',
                '-show_entries', 'stream=width,height',
                '-of', 'json',
                video_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            # Parse the output
            data = json.loads(result.stdout)
            if 'streams' in data and len(data['streams']) > 0:
                stream = data['streams'][0]
                return stream.get('width'), stream.get('height')

        except Exception as e:
            logger.warning(f"Could not get video dimensions: {e}")

        return None, None

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Sign a message with a private key using Ed25519.

        Args:
            private_key: The private key to sign with
            message: The message to sign

        Returns:
            The signature as bytes

        Raises:
            PymeowError: If signing fails
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            # Convert the private key to an Ed25519 private key
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

            # Sign the message (Ed25519 performs its own hashing)
            signature = private_key_obj.sign(message)

            return signature

        except Exception as e:
            logger.error(f"Error signing message: {e}", exc_info=True)
            raise PymeowError(f"Failed to sign message: {e}") from e

    async def _generate_key_pair(self) -> 'KeyPair':
        """
        Generate a new key pair for cryptographic operations.

        Returns:
            A new KeyPair instance

        Raises:
            PymeowError: If key generation fails
        """
        try:
            # Import KeyPair here to avoid circular imports
            from .auth import KeyPair
            return KeyPair.generate()
        except Exception as e:
            logger.error(f"Error generating key pair: {e}", exc_info=True)
            raise PymeowError(f"Failed to generate key pair: {e}") from e

    async def _send_ack(self, message_id: str, to: str, message_type: str):
        """
        Send an acknowledgment for a received message.

        Args:
            message_id: The ID of the message being acknowledged
            to: The JID of the message recipient
            message_type: Type of acknowledgment ('ack' or 'read')
        """
        ack_node = ProtocolNode(
            tag='ack',
            attrs={
                'id': message_id,
                'to': to,
                'type': message_type,
                'class': 'message'
            }
        )
        await self._send_node(ack_node)

    async def _send_presence(self, presence_type: str = 'available', to: Optional[str] = None):
        """
        Update the client's presence.

        Args:
            presence_type: Type of presence ('available', 'unavailable', 'composing', 'paused', etc.)
            to: Optional JID to send the presence to (for group chats)
        """
        attrs = {'type': presence_type}
        if to:
            attrs['to'] = to

        presence_node = ProtocolNode(tag='presence', attrs=attrs)
        await self._send_node(presence_node)

    async def _send_typing(self, jid: str, is_typing: bool = True):
        """
        Send a typing indicator to a chat.

        Args:
            jid: The JID of the chat
            is_typing: Whether the user is typing or has stopped typing
        """
        await self._send_presence(
            presence_type='composing' if is_typing else 'paused',
            to=jid
        )

    async def mark_messages_read(self, message_ids: Union[str, List[str]], chat_jid: str, participant_jid: Optional[str] = None) -> None:
        """
        Mark one or more messages as read.

        Args:
            message_ids: Single message ID or list of message IDs to mark as read
            chat_jid: The JID of the chat containing the messages
            participant_jid: For group messages, the JID of the message sender
        """
        if isinstance(message_ids, str):
            message_ids = [message_ids]

        if not message_ids:
            return

        # For a single message, use the simple protocol
        if len(message_ids) == 1:
            await self._send_receipt(
                message_ids[0],
                chat_jid,
                participant_jid,
                'read'
            )
            return

        # For multiple messages, use the list protocol
        attrs = {
            'to': chat_jid,
            'type': 'read'
        }

        if participant_jid:
            attrs['participant'] = participant_jid

        # Create list of message items
        items = []
        for msg_id in message_ids[1:]:  # First ID goes in the parent node
            items.append(ProtocolNode(tag='item', attrs={'id': msg_id}))

        # Create the list node if there are multiple messages
        list_node = ProtocolNode(tag='list', content=items) if items else None
        
        # First message ID goes in the parent node
        attrs['id'] = message_ids[0]
        
        receipt_node = ProtocolNode(
            tag='read',
            attrs=attrs,
            content=[list_node] if list_node else None
        )
        
        await self._send_node(receipt_node)

    async def mark_message_delivered(self, message_id: str, chat_jid: str, participant_jid: Optional[str] = None) -> None:
        """
        Mark a message as delivered.

        Args:
            message_id: The ID of the message to mark as delivered
            chat_jid: The JID of the chat containing the message
            participant_jid: For group messages, the JID of the message sender
        """
        await self._send_receipt(
            message_id,
            chat_jid,
            participant_jid,
            'delivered'
        )

    async def mark_message_played(self, message_id: str, chat_jid: str, participant_jid: Optional[str] = None) -> None:
        """
        Mark an audio/video message as played.

        Args:
            message_id: The ID of the message to mark as played
            chat_jid: The JID of the chat containing the message
            participant_jid: For group messages, the JID of the message sender
        """
        await self._send_receipt(
            message_id,
            chat_jid,
            participant_jid,
            'played'
        )

    async def _send_receipt(self, message_id: str, to_jid: str, participant: Optional[str], receipt_type: str) -> None:
        """
        Send a receipt for a message.

        Args:
            message_id: The ID of the message to send a receipt for
            to_jid: The JID to send the receipt to
            participant: Optional participant JID (for group messages)
            receipt_type: The type of receipt ('read', 'delivered', 'played')
        """
        attrs = {
            'id': message_id,
            'to': to_jid,
            'owner': 'false',
            'type': receipt_type
        }

        if participant:
            attrs['participant'] = participant

        receipt_node = ProtocolNode(tag=receipt_type, attrs=attrs)
        await self._send_node(receipt_node)

    async def _handle_receipt(self, node: ProtocolNode) -> None:
        """
        Handle an incoming receipt node.

        Args:
            node: The receipt protocol node
        """
        attrs = node.attrs
        receipt_type = attrs.get('type', 'delivered')
        message_ids = []
        
        # Get the main message ID
        message_id = attrs.get('id')
        if message_id:
            message_ids.append(message_id)
        
        # Check for additional message IDs in a list
        list_node = node.get_child('list')
        if list_node:
            for item in list_node.get_children('item'):
                if item_id := item.attrs.get('id'):
                    message_ids.append(item_id)
        
        if not message_ids:
            logger.warning(f"Received receipt with no message IDs: {node}")
            return
        
        # Get the sender and participant
        from_jid = attrs.get('from')
        participant = attrs.get('participant')
        
        # Create receipt info
        receipt_info = {
            'message_ids': message_ids,
            'from_jid': from_jid,
            'participant': participant,
            'receipt_type': receipt_type,
            'timestamp': int(time.time())
        }
        
        # Dispatch the receipt event
        event = {
            'type': 'receipt',
            'receipt': receipt_info
        }
        await self._dispatch_event(event)

    async def _send_node(self, node: ProtocolNode):
        """
        Send a protocol node to the server.

        Args:
            node: The protocol node to send
        """
        if not self._is_connected:
            raise ConnectionError("Not connected to WhatsApp")

        try:
            # Encode the node
            from .protocol import ProtocolEncoder
            encoder = ProtocolEncoder() # Updated: No keys passed
            data = encoder.encode(node)

            # Encrypt if needed (This encryption call will be moved to WebSocketClient later)
            if self._send_cipher:
                data = self._send_cipher.encrypt(data) # This line will be removed when WebSocketClient handles encryption

            # Send the data
            if self._websocket:
                await self._websocket.send_bytes(data)
        except Exception as e:
            logger.error(f"Failed to send node: {e}", exc_info=True)
            raise PymeowError(f"Failed to send node: {e}") from e

    async def _send_keepalive(self):
        """Send a keepalive ping to maintain the connection."""
        if not self._is_connected:
            return

        try:
            now = time.time()
            if now - self._last_ping >= self._keepalive_interval:
                if self._websocket:
                    await self._websocket.ping()
                    self._last_ping = now
        except Exception as e:
            logger.warning(f"Keepalive ping failed: {e}")
            await self._handle_ws_error(e)

    # Group Management Methods

    async def create_group(self, subject: str, participants: List[str]) -> Dict[str, Any]:
        """
        Create a new group.

        Args:
            subject: The group subject/name
            participants: List of participant JIDs to add to the group

        Returns:
            Dictionary containing group creation details
        """
        try:
            # Create the group node
            key = self._generate_message_id()
            participant_nodes = [
                ProtocolNode(tag='participant', attrs={'jid': jid})
                for jid in participants
            ]

            create_node = ProtocolNode(
                tag='create',
                attrs={'subject': subject},
                content=participant_nodes
            )

            # Send the create group IQ
            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',  # Changed from 'g.us' to properly route group invite requests
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[create_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    return {
                        'id': group_node.attrs.get('id'),
                        'subject': group_node.attrs.get('subject'),
                        'creation': int(group_node.attrs.get('creation', '0')),
                        'creator': group_node.attrs.get('creator')
                    }

            raise PymeowError("Failed to create group")

        except Exception as e:
            logger.error(f"Error creating group: {e}", exc_info=True)
            raise PymeowError(f"Failed to create group: {e}") from e


    async def set_group_subject(self, group_jid: str, subject: str) -> bool:
        """
        Update a group's subject (name).

        Args:
            group_jid: The JID of the group
            subject: The new subject/name for the group

        Returns:
            bool: True if the subject was updated successfully, False otherwise

        Raises:
            PymeowError: If updating the subject fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the subject node
            subject_node = ProtocolNode(
                tag='subject',
                attrs={},
                content=subject
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[subject_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the subject was updated successfully
            if response.attrs.get('type') == 'result':
                return True

            return False

        except Exception as e:
            logger.error(f"Error updating group subject: {e}", exc_info=True)
            raise PymeowError(f"Failed to update group subject: {e}") from e

    async def update_group_participants(
        self,
        group_jid: str,
        add_participants: Optional[List[str]] = None,
        remove_participants: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Add or remove participants from a group.

        Args:
            group_jid: The JID of the group
            add_participants: List of JIDs to add to the group
            remove_participants: List of JIDs to remove from the group

        Returns:
            Dictionary containing the result of the operation

        Raises:
            PymeowError: If the operation fails
            ValueError: If neither add_participants nor remove_participants is provided
        """
        if not add_participants and not remove_participants:
            raise ValueError("At least one of add_participants or remove_participants must be provided")

        try:
            iq_id = self._generate_message_id()
            participant_nodes = []

            # Create participant nodes for adding
            if add_participants:
                for jid in add_participants:
                    participant_nodes.append(ProtocolNode(
                        tag='participant',
                        attrs={'jid': jid, 'type': 'add'}
                    ))

            # Create participant nodes for removing
            if remove_participants:
                for jid in remove_participants:
                    participant_nodes.append(ProtocolNode(
                        tag='participant',
                        attrs={'jid': jid, 'type': 'remove'}
                    ))

            # Create the modify node
            modify_node = ProtocolNode(
                tag='modify',
                attrs={},
                content=participant_nodes
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[modify_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                modify_node = next((n for n in response.content if n.tag == 'modify'), None)
                if modify_node:
                    result = {'added': [], 'removed': [], 'failed': []}

                    # Process participant results
                    for p in modify_node.content:
                        if p.tag != 'participant':
                            continue

                        jid = p.attrs.get('jid')
                        type_ = p.attrs.get('type', '').lower()
                        error = p.attrs.get('error')

                        if error:
                            result['failed'].append({
                                'jid': jid,
                                'type': type_,
                                'error': error,
                                'code': p.attrs.get('code')
                            })
                        elif type_ == 'add':
                            result['added'].append(jid)
                        elif type_ == 'remove':
                            result['removed'].append(jid)

                    return result

            raise PymeowError("Failed to update group participants")

        except Exception as e:
            logger.error(f"Error updating group participants: {e}", exc_info=True)
            raise PymeowError(f"Failed to update group participants: {e}") from e

    async def leave_group(self, group_jid: str) -> bool:
        """
        Leave a group.

        Args:
            group_jid: The JID of the group to leave

        Returns:
            bool: True if successfully left the group, False otherwise

        Raises:
            PymeowError: If leaving the group fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the leave node
            leave_node = ProtocolNode(
                tag='leave',
                attrs={}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[leave_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the leave was successful
            if response.attrs.get('type') == 'result':
                return True

            return False

        except Exception as e:
            logger.error(f"Error leaving group {group_jid}: {e}", exc_info=True)
            raise PymeowError(f"Failed to leave group: {e}") from e

    async def join_group(self, invite_code: str) -> Dict[str, Any]:
        """
        Join a group using an invite link.

        Args:
            invite_code: The invite code from the group link (the part after chat.whatsapp.com/)

        Returns:
            Dictionary containing group information

        Raises:
            PymeowError: If joining the group fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the invite node with the code
            invite_node = ProtocolNode(
                tag='invite',
                attrs={'code': invite_code}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',  # Changed from 'g.us' to properly route group invite requests
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[invite_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    return {
                        'id': group_node.attrs.get('id'),
                        'subject': group_node.attrs.get('subject'),
                        'creator': group_node.attrs.get('creator'),
                        'creation': int(group_node.attrs.get('creation', '0')),
                        'participants': [
                            {'jid': p.attrs.get('jid'), 'role': p.attrs.get('type')}
                            for p in group_node.content if p.tag == 'participant'
                        ]
                    }

            raise PymeowError("Failed to join group")

        except Exception as e:
            logger.error(f"Error joining group: {e}", exc_info=True)
            raise PymeowError(f"Failed to join group: {e}") from e

    async def get_group_invite_link(self, group_jid: str, reset: bool = False) -> str:
        """
        Get or reset the group's invite link.

        Args:
            group_jid: The JID of the group
            reset: Whether to reset the invite link (generate a new one)

        Returns:
            The group invite link

        Raises:
            PymeowError: If the operation fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the invite link node
            invite_node = ProtocolNode(
                tag='invite',
                attrs={'type': 'reset' if reset else 'existing'}
            )

            # Create the query node
            query_node = ProtocolNode(
                tag='query',
                attrs={'xmlns': 'w:g2'},
                content=[invite_node]
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[query_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                query_node = next((n for n in response.content if n.tag == 'query'), None)
                if query_node:
                    invite_node = next((n for n in query_node.content if n.tag == 'invite'), None)
                    if invite_node and 'code' in invite_node.attrs:
                        return f"https://chat.whatsapp.com/{invite_node.attrs['code']}"

            raise PymeowError("Failed to get group invite link")

        except Exception as e:
            logger.error(f"Error getting group invite link: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group invite link: {e}") from e

    def _parse_group_node(self, group_node) -> Dict[str, Any]:
        """Parse a group node into a dictionary."""
        participants = []
        for participant_node in group_node.find_all('participant'):
            participants.append({
                'jid': participant_node.attrs.get('jid'),
                'is_admin': participant_node.attrs.get('type') == 'admin',
                'is_super_admin': participant_node.attrs.get('type') == 'superadmin'
            })

        return {
            'id': group_node.attrs.get('id'),
            'subject': group_node.attrs.get('subject'),
            'subject_owner': group_node.attrs.get('s_o'),
            'subject_time': int(group_node.attrs.get('s_t', '0')),
            'creation': int(group_node.attrs.get('creation', '0')),
            'creator': group_node.attrs.get('creator'),
            'participants': participants,
            'is_locked': group_node.attrs.get('locked') == 'true',
            'is_announcement': group_node.attrs.get('announcement') == 'true',
            'is_restricted': group_node.attrs.get('restrict') == 'true',
            'is_no_frequently_forwarded': group_node.attrs.get('no_frequently_forwarded') == 'true',
            'is_ephemeral': group_node.attrs.get('ephemeral') == 'true',
            'ephemeral_duration': int(group_node.attrs.get('ephemeral_duration', '0'))
        }

    async def _send_iq_and_wait(self, iq_node: ProtocolNode, iq_id: str, timeout: float = 30.0) -> ProtocolNode:
        """
        Send an IQ (Info/Query) and wait for the response.

        Args:
            iq_node: The IQ node to send
            iq_id: The IQ ID to wait for
            timeout: Timeout in seconds

        Returns:
            The response IQ node

        Raises:
            TimeoutError: If the response times out
            PymeowError: If the response indicates an error
        """
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending_requests[iq_id] = future

        try:
            await self._send_node(iq_node)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_requests.pop(iq_id, None)
            raise TimeoutError(f"IQ response timed out after {timeout} seconds")
        except Exception as e:
            self._pending_requests.pop(iq_id, None)
            raise PymeowError(f"Failed to send IQ: {e}") from e

    # Media Message Handling

    # Message Reactions
    async def send_reaction(self, message_id: str, chat_jid: str, emoji: str) -> Dict[str, Any]:
        """
        Send a reaction to a message or remove an existing reaction.

        Args:
            message_id: The ID of the message to react to
            chat_jid: The JID of the chat containing the message
            emoji: The emoji to react with (empty string to remove reaction)

        Returns:
            Dictionary with reaction status containing:
            - status: 'sent' or 'removed'
            - reaction_id: ID of the reaction message
            - message_id: ID of the original message
            - emoji: The emoji used (empty if removed)
            - timestamp: Unix timestamp of the reaction

        Raises:
            PymeowError: If the message doesn't exist, network error, or other issues
            ValueError: If the emoji is invalid
        """
        if not message_id or not isinstance(message_id, str):
            raise ValueError("Invalid message ID")

        if not chat_jid or not isinstance(chat_jid, str):
            raise ValueError("Invalid chat JID")

        if emoji and not isinstance(emoji, str):
            raise ValueError("Emoji must be a string")

        try:
            # Check if we already have a reaction to this message from us
            my_jid = f"{self._auth_state.device.id}@s.whatsapp.net"
            existing_reaction = None
            if hasattr(self, '_message_store') and self._message_store:
                existing_reaction = await self._message_store.get_reaction_by_sender(
                    message_id, my_jid
                )

            # If we're trying to remove a reaction but don't have one
            if not emoji and not existing_reaction:
                logger.warning(f"No existing reaction to remove for message {message_id}")
                return {
                    'status': 'no_reaction',
                    'message_id': message_id,
                    'emoji': '',
                    'timestamp': int(time.time())
                }

            # If we're trying to add the same reaction again
            if existing_reaction and existing_reaction.emoji == emoji:
                logger.warning(f"Duplicate reaction {emoji} to message {message_id}")
                return {
                    'status': 'duplicate',
                    'reaction_id': getattr(existing_reaction, 'id', ''),
                    'message_id': message_id,
                    'emoji': emoji,
                    'timestamp': int(time.time())
                }

            # Generate a new message ID for the reaction
            reaction_id = self._generate_message_id()

            # Create reaction node with proper attributes
            reaction_attrs = {
                'id': reaction_id,
                't': str(int(time.time())),
                'to': chat_jid,
                'type': 'reaction',
                'phash': '1'  # Indicates this is a reaction
            }

            # Create reaction node
            reaction_node = ProtocolNode(
                tag='reaction',
                attrs={
                    'id': message_id,  # Original message ID
                    't': str(int(time.time())),
                    'phash': '1',  # Indicates this is a reaction
                    'sender_jid': my_jid
                },
                content=emoji if emoji else None
            )

            # Create message node
            message_node = ProtocolNode(
                tag='message',
                attrs=reaction_attrs,
                content=[reaction_node]
            )

            # Send the reaction
            await self._enqueue_message(message_node)

            # Update the message store
            if hasattr(self, '_message_store') and self._message_store:
                if emoji:
                    # Add or update reaction
                    await self._message_store.add_reaction(
                        message_id,
                        my_jid,
                        emoji
                    )
                    action = 'sent'
                else:
                    # Remove reaction
                    await self._message_store.remove_reaction(
                        message_id,
                        my_jid
                    )
                    action = 'removed'
            else:
                action = 'sent' if emoji else 'removed'

            # Return reaction details
            return {
                'status': action,
                'reaction_id': reaction_id,
                'message_id': message_id,
                'emoji': emoji,
                'timestamp': int(time.time())
            }

        except Exception as e:
            error_msg = f"Failed to {'remove' if not emoji else 'send'} reaction"
            logger.error(f"{error_msg}: {e}", exc_info=True)
            raise PymeowError(f"{error_msg}: {e}") from e

    # Status Updates

    async def set_status(self, status: str, status_emoji: str = '', status_expiry: int = 0):
        """
        Set the user's status message.

        Args:
            status: The status text
            status_emoji: Optional emoji for the status
            status_expiry: Expiration time in seconds (0 for no expiration)
        """
        try:
            status_node = ProtocolNode(
                tag='status',
                attrs={
                    't': str(int(time.time())),
                    'type': 'set',
                    'emoji': status_emoji,
                    'expires': str(status_expiry) if status_expiry > 0 else ''
                },
                content=status
            )

            await self._send_node(status_node)

        except Exception as e:
            logger.error(f"Error setting status: {e}", exc_info=True)
            raise PymeowError(f"Failed to set status: {e}") from e

    async def get_status_updates(self, jids: List[str] = None):
        """
        Get status updates for specific users or all contacts.

        Args:
            jids: Optional list of JIDs to get status for. If None, gets all contacts.
        """
        try:
            user_nodes = []
            if jids:
                user_nodes = [
                    ProtocolNode('user', {'jid': jid})
                    for jid in jids
                ]

            query_node = ProtocolNode(
                tag='query',
                attrs={'type': 'contacts'},
                content=user_nodes
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'status'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_status_updates(response)

        except Exception as e:
            logger.error(f"Error getting status updates: {e}", exc_info=True)
            raise PymeowError(f"Failed to get status updates: {e}") from e

    def _parse_status_updates(self, response_node) -> List[Dict[str, Any]]:
        """Parse status updates from a response node."""
        statuses = []
        for user_node in response_node.find_all('user'):
            status_node = user_node.find('status')
            if status_node:
                statuses.append({
                    'jid': user_node.attrs.get('jid'),
                    'status': status_node.content,
                    't': int(status_node.attrs.get('t', '0')),
                    'emoji': status_node.attrs.get('emoji', ''),
                    'expires': int(status_node.attrs.get('expires', '0'))
                })
        return statuses

    # File Uploads

    async def upload_media(self, file_path: str, media_type: str = 'image') -> Dict[str, Any]:
        """
        Upload a media file to WhatsApp servers.

        Args:
            file_path: Path to the file to upload
            media_type: Type of media ('image', 'video', 'audio', 'document')

        Returns:
            Dictionary containing upload details (URL, hash, etc.)
        """
        try:
            import os
            import mimetypes
            from hashlib import sha256

            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Generate file hash
            file_hash = sha256(file_data).hexdigest()
            file_size = len(file_data)

            # Get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

            # Generate upload URL
            url = f"{self.BASE_URL}/mms/media/{file_hash}?type={mime_type}&mediatype={media_type}"

            # Upload file
            headers = {
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(file_size),
                'Origin': 'https://web.whatsapp.com',
                'Referer': 'https://web.whatsapp.com/'
            }

            async with self._session.put(url, data=file_data, headers=headers) as response:
                if response.status != 200:
                    raise PymeowError(f"Upload failed with status {response.status}")

                result = await response.json()

                return {
                    'url': result.get('url'),
                    'direct_path': result.get('direct_path'),
                    'media_key': result.get('media_key'),
                    'file_sha256': file_hash,
                    'file_enc_sha256': result.get('file_enc_sha256'),
                    'mimetype': mime_type,
                    'file_length': file_size,
                    'media_type': media_type
                }

        except Exception as e:
            logger.error(f"Error uploading media: {e}", exc_info=True)
            raise PymeowError(f"Failed to upload media: {e}") from e

    async def download_media(self, media_info: Dict[str, Any], output_path: str = None) -> Optional[bytes]:
        """
        Download media from WhatsApp servers.

        Args:
            media_info: Dictionary containing media info (from message or upload_media)
            output_path: Optional path to save the file. If None, returns the file data.

        Returns:
            The downloaded file data if output_path is None, otherwise None
        """
        try:
            if not media_info.get('url'):
                raise ValueError("No download URL available in media info")

            headers = {
                'Origin': 'https://web.whatsapp.com',
                'Referer': 'https://web.whatsapp.com/'
            }

            async with self._session.get(media_info['url'], headers=headers) as response:
                if response.status != 200:
                    raise PymeowError(f"Download failed with status {response.status}")

                data = await response.read()

                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(data)
                    return None
                return data

        except Exception as e:
            logger.error(f"Error downloading media: {e}", exc_info=True)
            raise PymeowError(f"Failed to download media: {e}") from e

    # Media Message Handler

    # Group Management

    async def add_group_participants(self, group_jid: str, participant_jids: List[str]):
        """
        Add participants to a group.

        Args:
            group_jid: The JID of the group
            participant_jids: List of JIDs to add to the group
        """
        try:
            participant_nodes = [
                ProtocolNode('participant', {'jid': jid})
                for jid in participant_jids
            ]

            add_node = ProtocolNode(
                tag='add',
                attrs={'request': 'interactive'},
                content=participant_nodes
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[add_node]
            )

            await self._send_iq_and_wait(iq_node, iq_id)

        except Exception as e:
            logger.error(f"Error adding group participants: {e}", exc_info=True)
            raise PymeowError(f"Failed to add group participants: {e}") from e

    async def remove_group_participants(self, group_jid: str, participant_jids: List[str]):
        """
        Remove participants from a group.

        Args:
            group_jid: The JID of the group
            participant_jids: List of JIDs to remove from the group
        """
        try:
            participant_nodes = [
                ProtocolNode('participant', {'jid': jid})
                for jid in participant_jids
            ]

            remove_node = ProtocolNode(
                tag='remove',
                attrs={'request': 'interactive'},
                content=participant_nodes
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[remove_node]
            )

            await self._send_iq_and_wait(iq_node, iq_id)

        except Exception as e:
            logger.error(f"Error removing group participants: {e}", exc_info=True)
            raise PymeowError(f"Failed to remove group participants: {e}") from e

    async def promote_group_admins(self, group_jid: str, participant_jids: List[str]):
        """
        Promote participants to group admins.

        Args:
            group_jid: The JID of the group
            participant_jids: List of JIDs to promote to admin
        """
        await self._modify_participant_roles(
            group_jid,
            participant_jids,
            'promote',
            "Failed to promote group admins"
        )

    async def demote_group_admins(self, group_jid: str, participant_jids: List[str]):
        """
        Demote group admins to regular participants.

        Args:
            group_jid: The JID of the group
            participant_jids: List of admin JIDs to demote
        """
        await self._modify_participant_roles(
            group_jid,
            participant_jids,
            'demote',
            "Failed to demote group admins"
        )

    async def _modify_participant_roles(self, group_jid: str, participant_jids: List[str],
                                      action: str, error_msg: str):
        """Internal method to modify participant roles."""
        try:
            participant_nodes = [
                ProtocolNode('participant', {'jid': jid})
                for jid in participant_jids
            ]

            modify_node = ProtocolNode(
                tag=action,
                content=participant_nodes
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[modify_node]
            )

            await self._send_iq_and_wait(iq_node, iq_id)

        except Exception as e:
            logger.error(f"{error_msg}: {e}", exc_info=True)
            raise PymeowError(f"{error_msg}: {e}") from e


    async def set_group_setting(self, group_jid: str, setting: str, value: bool) -> bool:
        """
        Update a group setting.

        Args:
            group_jid: The JID of the group
            setting: The setting to update. Can be one of:
                    - 'announcement': Whether only admins can send messages
                    - 'restrict': Whether only admins can edit group info
                    - 'ephemeral': Whether to use disappearing messages
            value: The new value for the setting

        Returns:
            bool: True if the setting was updated successfully, False otherwise

        Raises:
            PymeowError: If updating the setting fails
            ValueError: If an invalid setting is provided
        """
        valid_settings = {'announcement', 'restrict', 'ephemeral'}
        if setting not in valid_settings:
            raise ValueError(f"Invalid setting. Must be one of: {', '.join(valid_settings)}")

        try:
            iq_id = self._generate_message_id()

            # Create the setting node
            setting_node = ProtocolNode(
                tag=setting,
                attrs={
                    'value': str(value).lower(),
                    't': str(int(time.time()))
                }
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[setting_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the setting was updated successfully
            return response.attrs.get('type') == 'result'

        except Exception as e:
            logger.error(f"Error updating group setting {setting}: {e}", exc_info=True)
            raise PymeowError(f"Failed to update group setting {setting}: {e}") from e

    async def set_group_admins(self, group_jid: str, participant_jids: List[str], promote: bool = True) -> Dict[str, List[str]]:
        """
        Promote or demote participants to/from group admins.

        Args:
            group_jid: The JID of the group
            participant_jids: List of participant JIDs to modify admin status for
            promote: If True, promote to admin. If False, demote from admin.

        Returns:
            Dictionary containing lists of succeeded and failed operations:
            - 'succeeded': List of JIDs that were successfully updated
            - 'failed': List of dictionaries with 'jid' and 'error' for failed updates

        Raises:
            PymeowError: If the operation fails
        """
        if not participant_jids:
            raise ValueError("At least one participant JID must be provided")

        try:
            iq_id = self._generate_message_id()

            # Create participant nodes
            participant_nodes = []
            for jid in participant_jids:
                participant_nodes.append(ProtocolNode(
                    tag='participant',
                    attrs={
                        'jid': jid,
                        'type': 'promote' if promote else 'demote'
                    }
                ))

            # Create the modify node
            modify_node = ProtocolNode(
                tag='modify',
                attrs={},
                content=participant_nodes
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[modify_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            result = {'succeeded': [], 'failed': []}
            if response.attrs.get('type') == 'result':
                modify_node = next((n for n in response.content if n.tag == 'modify'), None)
                if modify_node:
                    for p in modify_node.content:
                        if p.tag != 'participant':
                            continue

                        jid = p.attrs.get('jid')
                        type_ = p.attrs.get('type', '').lower()
                        error = p.attrs.get('error')

                        if error or (type_ == 'promote' and not promote) or (type_ == 'demote' and promote):
                            result['failed'].append({
                                'jid': jid,
                                'error': error or 'unexpected_response',
                                'code': p.attrs.get('code')
                            })
                        else:
                            result['succeeded'].append(jid)

            return result

        except Exception as e:
            logger.error(f"Error {'promoting' if promote else 'demoting'} group admins: {e}", exc_info=True)
            raise PymeowError(f"Failed to {'promote' if promote else 'demote'} group admins: {e}") from e



    async def set_group_locked(self, group_jid: str, locked: bool = True) -> bool:
        """
        Set whether the group is locked (requires admin approval to join).

        Args:
            group_jid: The JID of the group
            locked: If True, requires admin approval to join. If False, anyone with the link can join.

        Returns:
            bool: True if the setting was updated successfully, False otherwise

        Raises:
            PymeowError: If updating the setting fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the lock node
            lock_node = ProtocolNode(
                tag='locked',
                attrs={'value': 'true' if locked else 'false'}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[lock_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the setting was updated successfully
            return response.attrs.get('type') == 'result'

        except Exception as e:
            logger.error(f"Error {'locking' if locked else 'unlocking'} group: {e}", exc_info=True)
            raise PymeowError(f"Failed to {'lock' if locked else 'unlock'} group: {e}") from e

    async def set_group_mute(self, group_jid: str, mute_duration: int = 0) -> bool:
        """
        Mute or unmute group notifications.

        Args:
            group_jid: The JID of the group
            mute_duration: Duration in seconds to mute for. Set to 0 to unmute.
                         Common values:
                         - 0: Unmute
                         - 3600: 1 hour
                         - 28800: 8 hours
                         - 604800: 1 week
                         - 2419200: 4 weeks (1 month)

        Returns:
            bool: True if the mute setting was updated successfully, False otherwise

        Raises:
            PymeowError: If updating the mute setting fails
            ValueError: If mute_duration is negative
        """
        if mute_duration < 0:
            raise ValueError("Mute duration cannot be negative")

        try:
            iq_id = self._generate_message_id()

            # Create the mute node
            mute_node = ProtocolNode(
                tag='mute',
                attrs={
                    'value': str(mute_duration),
                    't': str(int(time.time()))
                }
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[mute_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the mute setting was updated successfully
            return response.attrs.get('type') == 'result'

        except Exception as e:
            logger.error(f"Error {'muting' if mute_duration > 0 else 'unmuting'} group: {e}", exc_info=True)
            raise PymeowError(f"Failed to {'mute' if mute_duration > 0 else 'unmute'} group: {e}") from e

    async def get_group_participants(self, group_jid: str) -> List[Dict[str, Any]]:
        """
        Get the list of participants in a group.

        Args:
            group_jid: The JID of the group

        Returns:
            List of dictionaries containing participant information:
            - 'jid': The participant's JID
            - 'role': The participant's role ('admin', 'superadmin', or empty for regular member)
            - 'is_super_admin': Whether the participant is a super admin
            - 'is_admin': Whether the participant is an admin

        Raises:
            PymeowError: If fetching participants fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the list node
            list_node = ProtocolNode(
                tag='list',
                attrs={
                    'type': 'participants',
                    'smax': '1000'  # Max number of participants to return
                }
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[list_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                participants = []
                for child in response.content or []:
                    if child.tag == 'participant':
                        jid = child.attrs.get('jid')
                        if not jid:
                            continue

                        role = child.attrs.get('type', '').lower()
                        is_super_admin = child.attrs.get('sadmin') == 'true'
                        is_admin = role == 'admin' or is_super_admin

                        participants.append({
                            'jid': jid,
                            'role': role,
                            'is_super_admin': is_super_admin,
                            'is_admin': is_admin
                        })

                return participants

            raise PymeowError("Failed to get group participants: invalid response")

        except Exception as e:
            logger.error(f"Error getting group participants: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group participants: {e}") from e

    async def get_joined_groups(self) -> List[Dict[str, Any]]:
        """
        Get a list of all groups the user is participating in.

        Returns:
            List of dictionaries containing group information

        Raises:
            PymeowError: If there's an error fetching the group list
        """
        try:
            # Create the IQ node to request participating groups
            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 'g.us',
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[
                    ProtocolNode('participating'),
                    ProtocolNode('description')
                ]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            groups_node = response.get_child_by_tag('groups')
            if groups_node:
                groups = []
                for group_node in groups_node.get_children():
                    if group_node.tag == 'group':
                        groups.append({
                            'id': group_node.attrs.get('id'),
                            'subject': group_node.attrs.get('subject'),
                            'subject_owner': group_node.attrs.get('s_o'),
                            'subject_time': int(group_node.attrs.get('s_t', '0')),
                            'creation': int(group_node.attrs.get('creation', '0')),
                            'creator': group_node.attrs.get('creator'),
                            'participant_count': len(group_node.get_children_by_tag('participant'))
                        })
                return groups

            return []

        except Exception as e:
            logger.error(f"Error getting joined groups: {e}", exc_info=True)
            raise PymeowError(f"Failed to get joined groups: {e}") from e

    async def get_group_settings(self, group_jid: str) -> Dict[str, Any]:
        """
        Get the current settings for a group.

        Args:
            group_jid: The JID of the group

        Returns:
            Dictionary containing group settings:
            - 'announcement': Whether only admins can send messages (bool)
            - 'restrict': Whether only admins can edit group info (bool)
            - 'ephemeral': Ephemeral message duration in seconds (0 = off, 86400 = 24h, 604800 = 7d)
            - 'locked': Whether the group is locked (requires admin approval to join) (bool)
            - 'incognito': Whether the group is incognito (bool)
            - 'no_frequently_forwarded': Whether to disable frequently forwarded messages (bool)
            - 'membership_approval_mode': Whether group join requires admin approval (bool)

        Raises:
            PymeowError: If the group settings can't be retrieved
        """
        try:
            # First get the group info which contains most settings
            group_info = await self.get_group_info(group_jid)
            
            # Then get ephemeral settings separately as they might not be in the group info
            ephemeral = 0
            try:
                iq_id = self._generate_message_id()
                iq_node = ProtocolNode(
                    tag='iq',
                    attrs={
                        'id': iq_id,
                        'to': group_jid,
                        'type': 'get',
                        'xmlns': 'w:g2'
                    },
                    content=[
                        ProtocolNode('ephemeral')
                    ]
                )
                response = await self._send_iq_and_wait(iq_node, iq_id)
                if response.attrs.get('type') == 'result':
                    ephemeral_node = response.get_child_by_tag('ephemeral')
                    if ephemeral_node:
                        ephemeral = int(ephemeral_node.attrs.get('duration', '0'))
            except Exception as e:
                logger.warning(f"Could not fetch ephemeral settings: {e}")

            return {
                'announcement': group_info.get('announcement', False),
                'restrict': group_info.get('restrict', False),
                'ephemeral': ephemeral,
                'locked': group_info.get('locked', False),
                'incognito': group_info.get('incognito', False),
                'no_frequently_forwarded': group_info.get('no_frequently_forwarded', False),
                'membership_approval_mode': group_info.get('membership_approval_mode', False)
            }

        except Exception as e:
            logger.error(f"Error getting group settings: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group settings: {e}") from e

    async def get_group_info(self, group_jid: str) -> Dict[str, Any]:
        """
        Get detailed information about a group.

        Args:
            group_jid: The JID of the group

        Returns:
            Dictionary containing group information:
            - 'id': The group JID
            - 'subject': The group subject/name
            - 'subject_owner': JID of who set the subject
            - 'subject_time': When the subject was last set (timestamp)
            - 'creation': When the group was created (timestamp)
            - 'creator': JID of the group creator
            - 'description': Group description (if any)
            - 'description_id': ID of the description
            - 'description_time': When description was set (timestamp)
            - 'locked': Whether the group is locked
            - 'announcement': Whether only admins can send messages
            - 'restrict': Whether only admins can edit group info
            - 'participants': List of participants with their roles
            - 'participant_count': Number of participants
            - 'pending_requests': Number of pending join requests (if any)

        Raises:
            PymeowError: If fetching group info fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the query node
            query_node = ProtocolNode(
                tag='query',
                attrs={'request': 'interactive'}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[query_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    group_info = group_node.attrs
                    participants = []

                    # Parse participants
                    participant_nodes = [n for n in group_node.content if n.tag == 'participant']
                    for p in participant_nodes:
                        participants.append({
                            'jid': p.attrs.get('jid'),
                            'role': p.attrs.get('type', 'regular'),
                            'is_super_admin': p.attrs.get('is_super_admin', 'false') == 'true',
                            'is_admin': p.attrs.get('type') == 'admin' or p.attrs.get('is_super_admin') == 'true'
                        })

                    return {
                        'id': group_info.get('id') or group_jid,
                        'subject': group_info.get('subject'),
                        'subject_owner': group_info.get('s_o'),
                        'subject_time': int(group_info.get('s_t', '0')),
                        'creation': int(group_info.get('creation', '0')),
                        'creator': group_info.get('creator'),
                        'description': group_info.get('description'),
                        'description_id': group_info.get('desc_id'),
                        'description_time': int(group_info.get('desc_time', '0')),
                        'locked': group_info.get('locked') == 'true',
                        'announcement': group_info.get('announcement') == 'true',
                        'restrict': group_info.get('restrict') == 'true',
                        'participants': participants,
                        'participant_count': len(participants),
                        'pending_requests': int(group_info.get('pending_requests', '0'))
                    }

            raise PymeowError("Failed to get group info: invalid response")

        except Exception as e:
            logger.error(f"Error getting group info: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group info: {e}") from e

    async def set_group_setting(self, group_jid: str, setting: str, value: Any) -> bool:
        """
        Update a group setting.

        Args:
            group_jid: The JID of the group
            setting: The setting to update. Can be one of:
                   - 'announcement': Whether only admins can send messages (bool)
                   - 'restrict': Whether only admins can edit group info (bool)
                   - 'ephemeral': Duration for disappearing messages in seconds (0 = off, 86400 = 1 day, 604800 = 1 week)
                   - 'locked': Whether the group is locked (bool)
                   - 'incognito': Whether the group is incognito (bool)
                   - 'no_frequently_forwarded': Disable frequently forwarded messages (bool)
                   - 'membership_approval_mode': Whether admin approval is required to join (bool)
            value: The new value for the setting

        Returns:
            bool: True if the setting was updated successfully

        Raises:
            PymeowError: If the setting update fails
            ValueError: If an invalid setting is provided
        """
        valid_settings = {
            'announcement': 'announcement',
            'restrict': 'restrict',
            'ephemeral': 'ephemeral',
            'locked': 'locked',
            'incognito': 'incognito',
            'no_frequently_forwarded': 'no_frequently_forwarded',
            'membership_approval_mode': 'membership_approval_mode'
        }

        if setting not in valid_settings:
            raise ValueError(f"Invalid setting. Must be one of: {', '.join(valid_settings.keys())}")

        try:
            iq_id = self._generate_message_id()

            # Create the setting node
            setting_value = 'true' if isinstance(value, bool) and value else str(value)
            setting_node = ProtocolNode(
                tag=valid_settings[setting],
                attrs={'value': setting_value}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[setting_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the setting was updated successfully
            if response.attrs.get('type') == 'result':
                return True

            raise PymeowError("Failed to update group setting: invalid response")

        except Exception as e:
            logger.error(f"Error updating group setting {setting}: {e}", exc_info=True)
            raise PymeowError(f"Failed to update group setting: {e}") from e

    async def set_group_icon(self, group_jid: str, image_path: str) -> Optional[Dict[str, Any]]:
        """
        Set or update the group's profile picture.

        Args:
            group_jid: The JID of the group
            image_path: Path to the image file to set as group icon

        Returns:
            Dictionary containing the result of the operation with keys:
            - 'url': URL of the uploaded icon
            - 'tag': The tag/hash of the icon
            - 'id': The ID of the icon

        Raises:
            PymeowError: If setting the icon fails
            FileNotFoundError: If the image file doesn't exist
            ValueError: If the file is not a valid image
        """
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")

        try:
            # Read and validate the image
            with open(image_path, 'rb') as f:
                image_data = f.read()

            # Validate it's an image using Pillow
            try:
                from io import BytesIO
                Image.open(BytesIO(image_data)).verify()
            except Exception as e:
                raise ValueError(f"File is not a valid image: {e}")

            # Generate a unique ID for the icon
            icon_id = self._generate_message_id()

            # Create a temporary file to upload
            temp_file_path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(image_path)[1]) as temp_file:
                    temp_file.write(image_data)
                    temp_file_path = temp_file.name

                # Upload the image to get a URL
                media_info = await self.upload_media(
                    file_path=temp_file_path,
                    media_type='image'
                )

                if not media_info or 'url' not in media_info or 'media_key' not in media_info:
                    raise PymeowError("Invalid response from media upload")

                # Create the picture node
                picture_node = ProtocolNode(
                    tag='picture',
                    attrs={
                        'id': icon_id,
                        'type': 'image',
                        'url': media_info['url'],
                        'media_key': media_info['media_key'],
                        'mimetype': media_info.get('mimetype', 'image/jpeg')
                    }
                )

                # Create the IQ node
                iq_id = self._generate_message_id()
                iq_node = ProtocolNode(
                    tag='iq',
                    attrs={
                        'id': iq_id,
                        'to': group_jid,
                        'type': 'set',
                        'xmlns': 'w:profile:picture'
                    },
                    content=[picture_node]
                )

                # Send and wait for response
                response = await self._send_iq_and_wait(iq_node, iq_id)

                # Check if the icon was set successfully
                if response.attrs.get('type') != 'result':
                    raise PymeowError("Failed to set group icon")

                return {
                    'url': media_info['url'],
                    'tag': media_info['media_key'][:32],  # First 32 chars as tag
                    'id': icon_id
                }

            except Exception as upload_error:
                logger.error(f"Error uploading group icon: {upload_error}", exc_info=True)
                raise PymeowError(f"Failed to upload group icon: {upload_error}") from upload_error

            finally:
                # Clean up the temporary file if it was created
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.unlink(temp_file_path)
                    except OSError as e:
                        logger.warning(f"Failed to clean up temporary file: {e}")

        except Exception as e:
            logger.error(f"Error setting group icon: {e}", exc_info=True)
            if not isinstance(e, (PymeowError, FileNotFoundError, ValueError)):
                raise PymeowError(f"Failed to set group icon: {e}") from e
            raise  # Re-raise the original error if it's one of the expected types

    async def remove_group_icon(self, group_jid: str) -> bool:
        """
        Remove the group's profile picture.

        Args:
            group_jid: The JID of the group

        Returns:
            bool: True if the icon was removed successfully, False otherwise

        Raises:
            PymeowError: If removing the icon fails
        """
        try:
            # Create a delete picture node
            delete_node = ProtocolNode(
                tag='delete',
                attrs={}
            )

            # Create the IQ node
            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:profile:picture'
                },
                content=[delete_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the icon was removed successfully
            return response.attrs.get('type') == 'result'

        except Exception as e:
            logger.error(f"Error removing group icon: {e}", exc_info=True)
            raise PymeowError(f"Failed to remove group icon: {e}") from e

    async def get_group_invite_qr(self, group_jid: str) -> Dict[str, Any]:
        """
        Get a QR code for inviting people to a group.

        Args:
            group_jid: The JID of the group

        Returns:
            Dictionary containing:
            - 'code': The invite code (string)
            - 'expiration': Expiration timestamp in seconds since epoch (int)
            - 'invite_url': Full invite URL (string)

        Raises:
            PymeowError: If getting the QR code fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the QR code node
            qr_node = ProtocolNode(
                tag='invite',
                attrs={'type': 'invite'}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[qr_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                invite_node = next((n for n in response.content if n.tag == 'invite'), None)
                if invite_node:
                    code = invite_node.attrs.get('code', '')
                    expiration = int(invite_node.attrs.get('expiration', '0'))
                    return {
                        'code': code,
                        'expiration': expiration,
                        'invite_url': f'https://chat.whatsapp.com/{code}'
                    }

            raise PymeowError("Failed to get group invite QR code")

        except Exception as e:
            logger.error(f"Error getting group invite QR code: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group invite QR code: {e}") from e

    async def join_group_via_invite(self, invite_code: str) -> Dict[str, Any]:
        """
        Join a group using an invite link.

        Args:
            invite_code: The invite code from the group link (the part after chat.whatsapp.com/)

        Returns:
            Dictionary containing:
            - 'jid': The group JID (string)
            - 'subject': Group name (string)
            - 'creator': JID of the group creator (string)
            - 'creation': Creation timestamp (int)
            - 'participants': List of participant dictionaries with 'jid' and 'role' keys
            - 'status': Status of the join request ('joined' or 'approval_required')
            - 'approval_required': Whether admin approval is required to join (bool)

        Raises:
            PymeowError: If joining the group fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the invite node with the code
            invite_node = ProtocolNode(
                tag='invite',
                attrs={'code': invite_code}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',  # Changed from 'g.us' to properly route group invite requests
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[invite_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                # Check for membership approval required
                membership_node = next((n for n in response.content if n.tag == 'membership_approval_request'), None)
                if membership_node:
                    return {
                        'status': 'approval_required',
                        'group_jid': membership_node.attrs.get('jid'),
                        'approval_required': True
                    }

                # Standard group join success
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    return {
                        'status': 'joined',
                        'jid': group_node.attrs.get('id'),
                        'subject': group_node.attrs.get('subject'),
                        'creator': group_node.attrs.get('creator'),
                        'creation': int(group_node.attrs.get('creation', '0')),
                        'participants': [
                            {'jid': p.attrs.get('jid'), 'role': p.attrs.get('type')}
                            for p in group_node.content if p.tag == 'participant'
                        ],
                        'approval_required': False
                    }

            raise PymeowError("Failed to join group via invite")

        except Exception as e:
            logger.error(f"Error joining group via invite: {e}", exc_info=True)
            raise PymeowError(f"Failed to join group via invite: {e}") from e

    async def get_group_invite_info(self, invite_code: str) -> Dict[str, Any]:
        """
        Get information about a group invite.

        Args:
            invite_code: The invite code (from URL like https://chat.whatsapp.com/CODE)

        Returns:
            Dictionary containing:
            - 'id': The group JID (string)
            - 'subject': Group name (string)
            - 'creator': JID of the group creator (string)
            - 'creation': Creation timestamp (int)
            - 'participant_count': Number of participants (int)
            - 'description': Group description (string, optional)
            - 'invite_code': The invite code (string)
            - 'expiration': Expiration timestamp (int, 0 if no expiration)
            - 'is_default': Whether this is the default invite (bool)

        Raises:
            PymeowError: If getting the invite info fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the invite info node
            invite_node = ProtocolNode(
                tag='invite',
                attrs={'code': invite_code}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',  # Changed from 'g.us' to properly route group invite requests
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[invite_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    participants = []
                    for p in group_node.content:
                        if p.tag == 'participant':
                            participants.append({
                                'jid': p.attrs.get('jid'),
                                'is_admin': p.attrs.get('type') == 'admin',
                                'is_super_admin': p.attrs.get('is_super_admin') == 'true'
                            })

                    return {
                        'id': group_node.attrs.get('id', ''),
                        'subject': group_node.attrs.get('subject', ''),
                        'creator': group_node.attrs.get('creator', ''),
                        'creation': int(group_node.attrs.get('creation', '0')),
                        'participant_count': len(participants),
                        'description': group_node.attrs.get('description'),
                        'invite_code': invite_code,
                        'expiration': int(group_node.attrs.get('expiration', '0')),
                        'is_default': group_node.attrs.get('default') == 'true',
                        'participants': participants
                    }

            raise PymeowError("Failed to get group invite info")

        except Exception as e:
            logger.error(f"Error getting group invite info: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group invite info: {e}") from e

    async def set_group_description(self, group_jid: str, description: str) -> Dict[str, Any]:
        """
        Set or update the group's description.

        Args:
            group_jid: The JID of the group
            description: The new description text (empty string to remove)

        Returns:
            Dictionary containing:
            - 'id': The description ID (string)
            - 'description': The description text (string)
            - 'time': Timestamp when the description was set (int)

        Raises:
            PymeowError: If setting the description fails
        """
        try:
            # Generate a unique ID for the description
            desc_id = self._generate_message_id()
            timestamp = int(time.time())

            # Create the description node
            desc_node = ProtocolNode(
                tag='description',
                attrs={
                    'id': desc_id,
                    'time': str(timestamp)
                },
                content=[description] if description else None
            )

            # Create the IQ node
            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'set',
                    'xmlns': 'w:g2'
                },
                content=[desc_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Check if the description was set successfully
            if response.attrs.get('type') != 'result':
                raise PymeowError("Failed to set group description")

            return {
                'id': desc_id,
                'description': description,
                'time': timestamp
            }

        except Exception as e:
            logger.error(f"Error setting group description: {e}", exc_info=True)
            raise PymeowError(f"Failed to set group description: {e}") from e

    async def get_group_settings(self, group_jid: str) -> Dict[str, Any]:
        """
        Get the current settings for a group.

        Args:
            group_jid: The JID of the group

        Returns:
            Dictionary containing group settings:
            - 'announcement': Whether only admins can send messages (bool)
            - 'restrict': Whether only admins can edit group info (bool)
            - 'locked': Whether the group is locked (requires admin approval to join) (bool)
            - 'ephemeral': Ephemeral message duration in seconds (0 = off, 86400 = 24h, 604800 = 7d)
            - 'incognito': Whether the group is incognito (bool)
            - 'no_frequently_forwarded': Whether to disable frequently forwarded messages (bool)
            - 'membership_approval_mode': Whether membership approval is required (bool)

        Raises:
            PymeowError: If getting the settings fails
        """
        try:
            iq_id = self._generate_message_id()

            # Create the query node
            query_node = ProtocolNode(
                tag='query',
                attrs={'request': 'group'}
            )

            # Create the IQ node
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': group_jid,
                    'type': 'get',
                    'xmlns': 'w:g2'
                },
                content=[query_node]
            )

            # Send and wait for response
            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            if response.attrs.get('type') == 'result':
                group_node = next((n for n in response.content if n.tag == 'group'), None)
                if group_node:
                    return {
                        'announcement': group_node.attrs.get('announcement') == 'true',
                        'restrict': group_node.attrs.get('restrict') == 'true',
                        'locked': group_node.attrs.get('locked') == 'true',
                        'ephemeral': int(group_node.attrs.get('ephemeral', '0')),
                        'incognito': group_node.attrs.get('incognito') == 'true',
                        'no_frequently_forwarded': group_node.attrs.get('no_frequently_forwarded') == 'true',
                        'membership_approval_mode': group_node.attrs.get('membership_approval_mode') == 'true'
                    }

            raise PymeowError("Failed to get group settings")

        except Exception as e:
            logger.error(f"Error getting group settings: {e}", exc_info=True)
            raise PymeowError(f"Failed to get group settings: {e}") from e

    # Contact Management

    async def get_privacy_settings(self) -> PrivacySettings:
        """
        Get the current privacy settings for the account.

        Returns:
            A dictionary containing the current privacy settings

        Raises:
            PymeowError: If there's an error fetching the privacy settings
        """
        try:
            iq_id = self._generate_message_id()
            privacy_node = ProtocolNode('privacy')

            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'privacy'
                },
                content=[privacy_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)

            # Parse the response
            settings: PrivacySettings = {}
            for child in response.content or []:
                if child.tag == 'category':
                    name = child.attrs.get('name', '')
                    value = child.attrs.get('value', '')
                    if name in ['last', 'last_seen']:
                        settings['last_seen'] = PrivacySetting(value)
                    elif name in ['profile', 'profile_photo']:
                        settings['profile_photo'] = PrivacySetting(value)
                    elif name == 'status':
                        settings['status'] = PrivacySetting(value)
                    elif name == 'about':
                        settings['about'] = PrivacySetting(value)
                    elif name == 'groups':
                        settings['groups'] = PrivacySetting(value)
                    elif name == 'calls':
                        settings['calls'] = PrivacySetting(value)

            return settings

        except Exception as e:
            logger.error(f"Error getting privacy settings: {e}", exc_info=True)
            raise PymeowError(f"Failed to get privacy settings: {e}") from e

    async def set_privacy_setting(self, setting: str, value: PrivacySetting) -> bool:
        """
        Update a privacy setting.

        Args:
            setting: The setting to update. Can be one of:
                   - 'last_seen': Who can see your last seen
                   - 'profile_photo': Who can see your profile photo
                   - 'status': Who can see your status
                   - 'about': Who can see your about info
                   - 'groups': Who can add you to groups
                   - 'calls': Who can call you
            value: The new privacy setting value (PrivacySetting enum)

        Returns:
            bool: True if the setting was updated successfully, False otherwise

        Raises:
            PymeowError: If there's an error updating the privacy setting
        """
        try:
            iq_id = self._generate_message_id()

            # Map setting names to WhatsApp's expected format
            setting_map = {
                'last_seen': 'last',
                'profile_photo': 'profile',
                'status': 'status',
                'about': 'about',
                'groups': 'groups',
                'calls': 'calls'
            }

            setting_name = setting_map.get(setting, setting)

            # Create the privacy node
            privacy_node = ProtocolNode(
                tag='privacy',
                attrs={},
                content=[
                    ProtocolNode(
                        tag='category',
                        attrs={
                            'name': setting_name,
                            'value': value.value
                        }
                    )
                ]
            )

            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'set',
                    'xmlns': 'privacy'
                },
                content=[privacy_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return response.attrs.get('type') == 'result'

        except Exception as e:
            logger.error(f"Error setting privacy setting {setting}: {e}", exc_info=True)
            raise PymeowError(f"Failed to set privacy setting: {e}") from e

    # Convenience methods for common privacy settings

    async def get_last_seen_privacy(self) -> PrivacySetting:
        """
        Get the current 'last seen' privacy setting.

        Returns:
            PrivacySetting: The current last seen privacy setting
        """
        settings = await self.get_privacy_settings()
        return settings.get('last_seen', PrivacyValue.ALL)

    async def set_last_seen_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the 'last seen' privacy setting.

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        return await self.set_privacy_setting('last_seen', value)

    async def get_profile_photo_privacy(self) -> PrivacySetting:
        """
        Get the current profile photo privacy setting.

        Returns:
            PrivacySetting: The current profile photo privacy setting
        """
        settings = await self.get_privacy_settings()
        return settings.get('profile_photo', PrivacySetting.ALL)

    async def set_profile_photo_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the profile photo privacy setting.

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        return await self.set_privacy_setting('profile_photo', value)

    async def get_status_privacy(self) -> PrivacySetting:
        """
        Get the current status privacy setting.

        Returns:
            PrivacySetting: The current status privacy setting
        """
        settings = await self.get_privacy_settings()
        return settings.get('status', PrivacySetting.ALL)

    async def set_status_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the status privacy setting.

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        return await self.set_privacy_setting('status', value)

    async def get_about_privacy(self) -> PrivacySetting:
        """
        Get the current 'about' privacy setting.

        Returns:
            PrivacySetting: The current about privacy setting value
        """
        settings = await self.get_privacy_settings()
        return settings.get('about', PrivacySetting.ALL)

    async def set_about_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the 'about' privacy setting.

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        return await self.set_privacy_setting('about', value)

    async def get_groups_privacy(self) -> PrivacySetting:
        """
        Get the current groups privacy setting (who can add you to groups).

        Returns:
            PrivacySetting: The current groups privacy setting
        """
        settings = await self.get_privacy_settings()
        return settings.get('groups', PrivacySetting.ALL)

    async def set_groups_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the groups privacy setting (who can add you to groups).

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        if value not in [PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.CONTACT_BLACKLIST]:
            raise ValueError("Groups privacy can only be set to ALL, CONTACTS, or CONTACT_BLACKLIST")
        return await self.set_privacy_setting('groups', value)

    async def get_calls_privacy(self) -> PrivacySetting:
        """
        Get the current calls privacy setting (who can call you).

        Returns:
            PrivacySetting: The current calls privacy setting
        """
        settings = await self.get_privacy_settings()
        return settings.get('calls', PrivacySetting.ALL)

    async def set_calls_privacy(self, value: PrivacySetting) -> bool:
        """
        Set the calls privacy setting (who can call you).

        Args:
            value: The new privacy setting value

        Returns:
            bool: True if the setting was updated successfully
        """
        if value not in [PrivacySetting.ALL, PrivacySetting.CONTACTS, PrivacySetting.NONE]:
            raise ValueError("Calls privacy can only be set to ALL, CONTACTS, or NONE")
        return await self.set_privacy_setting('calls', value)

    async def get_contacts(self) -> List[Dict[str, Any]]:
        """
        Get the user's contact list.

        Returns:
            List of contact dictionaries
        """
        try:
            iq_id = self._generate_message_id()
            query_node = ProtocolNode('query')

            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:contacts'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_contacts(response)

        except Exception as e:
            logger.error(f"Error getting contacts: {e}", exc_info=True)
            raise PymeowError(f"Failed to get contacts: {e}") from e

    def _parse_contacts(self, response_node) -> List[Dict[str, Any]]:
        """Parse contacts from a response node."""
        contacts = []
        for item in response_node.find_all('item'):
            jid = item.attrs.get('jid')
            if not jid:
                continue

            contact = {
                'jid': jid,
                'name': item.attrs.get('name', ''),
                'notify': item.attrs.get('notify', ''),
                'short': item.attrs.get('short', ''),
                'verified_name': item.attrs.get('vname', ''),
                'labels': item.attrs.get('labels', '').split(',')
            }

            # Parse additional info if available
            for child in item.content or []:
                if isinstance(child, ProtocolNode):
                    if child.tag == 'status':
                        contact['status'] = child.content
                    elif child.tag == 'img' and 'url' in child.attrs:
                        contact['img_url'] = child.attrs['url']

            contacts.append(contact)

        return contacts


    # Media Message Handler

    # Message History Synchronization

    async def sync_message_history(self, last_message_timestamp: int = 0, limit: int = 50,
                                chat_jid: str = None) -> List[Dict[str, Any]]:
        """
        Synchronize message history.

        Args:
            last_message_timestamp: Timestamp of the last received message (for pagination)
            limit: Maximum number of messages to retrieve (1-1000)
            chat_jid: Optional chat JID to sync messages for a specific chat

        Returns:
            List of message dictionaries
        """
        try:
            # Ensure limit is within bounds
            limit = max(1, min(1000, limit))

            # Build sync query
            query_attrs = {
                'count': str(limit),
                'index': '0',
                'type': 'chat',
                'epoch': str(self._message_epoch)
            }

            if last_message_timestamp > 0:
                query_attrs['after'] = str(last_message_timestamp)

            if chat_jid:
                query_attrs['jid'] = chat_jid

            query_node = ProtocolNode(
                tag='query',
                attrs=query_attrs
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:m'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_message_list(response)

        except Exception as e:
            logger.error(f"Error syncing messages: {e}", exc_info=True)
            raise PymeowError(f"Failed to sync messages: {e}") from e

    def _parse_message_list(self, response_node) -> List[Dict[str, Any]]:
        """Parse a list of messages from a sync response."""
        messages = []
        for msg_node in response_node.find_all('message'):
            try:
                message = {
                    'id': msg_node.attrs.get('id'),
                    'from': msg_node.attrs.get('from'),
                    'to': msg_node.attrs.get('to'),
                    'timestamp': int(msg_node.attrs.get('t', '0')),
                    'type': msg_node.attrs.get('type'),
                    'status': msg_node.attrs.get('status'),
                    'content': None,
                    'media': None
                }

                # Parse message content
                content_node = msg_node.find('body')
                if content_node and content_node.content:
                    message['content'] = content_node.content

                # Parse media info if present
                media_node = msg_node.find('media')
                if media_node:
                    message['media'] = {
                        'type': media_node.attrs.get('type'),
                        'url': media_node.attrs.get('url'),
                        'mimetype': media_node.attrs.get('mimetype'),
                        'size': int(media_node.attrs.get('size', '0')),
                        'caption': media_node.attrs.get('caption')
                    }

                messages.append(message)

            except Exception as e:
                logger.warning(f"Error parsing message node: {e}", exc_info=True)

        return messages

    # End-to-End Encryption Helpers

    async def generate_pre_keys(self, count: int = 50) -> List[Dict[str, Any]]:
        """
        Generate pre-keys for end-to-end encryption.

        Args:
            count: Number of pre-keys to generate (1-255)

        Returns:
            List of generated pre-keys
        """
        try:
            count = max(1, min(255, count))

            iq_id = self._generate_message_id()
            list_node = ProtocolNode(
                tag='list',
                attrs={'count': str(count)}
            )

            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'set',
                    'xmlns': 'w:pkmsg'
                },
                content=[list_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_pre_keys(response)

        except Exception as e:
            logger.error(f"Error generating pre-keys: {e}", exc_info=True)
            raise PymeowError(f"Failed to generate pre-keys: {e}") from e

    def _parse_pre_keys(self, response_node) -> List[Dict[str, Any]]:
        """Parse pre-keys from a response node."""
        pre_keys = []
        for key_node in response_node.find_all('key'):
            try:
                pre_key = {
                    'id': int(key_node.attrs.get('id', '0')),
                    'key': key_node.content,
                    'signature': key_node.attrs.get('signature')
                }
                pre_keys.append(pre_key)
            except (ValueError, AttributeError) as e:
                logger.warning(f"Error parsing pre-key: {e}")
        return pre_keys

    async def upload_pre_keys(self, pre_keys: List[Dict[str, Any]]):
        """
        Upload pre-keys to the server.

        Args:
            pre_keys: List of pre-keys to upload
        """
        try:
            key_nodes = []
            for key in pre_keys:
                key_node = ProtocolNode(
                    tag='key',
                    attrs={
                        'id': str(key['id']),
                        'signature': key.get('signature', '')
                    },
                    content=key['key']
                )
                key_nodes.append(key_node)

            list_node = ProtocolNode(
                tag='list',
                content=key_nodes
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'set',
                    'xmlns': 'w:pkmsg'
                },
                content=[list_node]
            )

            await self._send_iq_and_wait(iq_node, iq_id)

        except Exception as e:
            logger.error(f"Error uploading pre-keys: {e}", exc_info=True)
            raise PymeowError(f"Failed to upload pre-keys: {e}") from e

    async def refresh_signed_pre_key(self):
        """
        Generate and upload a new signed pre-key for secure key rotation.

        This method:
        1. Generates a new ephemeral key pair
        2. Signs the public key with the identity key
        3. Uploads the signed pre-key to the server

        Raises:
            PymeowError: If key generation, signing, or upload fails
        """
        try:
            # Generate a new ephemeral key pair for the signed pre-key
            key_pair = await self._generate_key_pair()

            # Get the identity key for signing
            identity_key_pair = await self.get_identity_key_pair()
            private_key = identity_key_pair.get('private_key')

            if not private_key:
                raise PymeowError("No identity private key available for signing")

            # Sign the public key with the identity key
            signature = self._crypto.sign(
                private_key=private_key,
                message=key_pair.get_public_key_bytes(),
            )

            # Create the signed pre-key structure
            signed_pre_key = {
                'key_id': int(time.time() * 1000),  # Use timestamp as key ID
                'public_key': key_pair.get_public_key_bytes(),
                'signature': signature,
                'timestamp': int(time.time())
            }

            # Upload the signed pre-key to the server
            upload_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': self._generate_message_id(),
                    'type': 'set',
                    'xmlns': 'encrypt',
                    'to': 's.whatsapp.net'
                },
                content=[
                    ProtocolNode(
                        tag='registration',
                        attrs={'xmlns': 'urn:xmpp:whatsapp:reg'}
                    ),
                    ProtocolNode(
                        tag='key',
                        attrs={
                            'id': str(signed_pre_key['key_id']),
                            'algo': 'ed25519',
                            'type': 'pkmsg',
                            'signature': base64.b64encode(signed_pre_key['signature']).decode('ascii')
                        },
                        content=signed_pre_key['public_key']
                    )
                ]
            )

            # Send the upload request
            await self._send_node(upload_node)

            # Update the client's state with the new signed pre-key
            self._signed_pre_key = signed_pre_key

            logger.info(f"Successfully refreshed signed pre-key {signed_pre_key['key_id']}")

        except Exception as e:
            logger.error(f"Error refreshing signed pre-key: {e}", exc_info=True)
            raise PymeowError(f"Failed to refresh signed pre-key: {e}") from e

    async def get_identity_key_pair(self) -> Dict[str, bytes]:
        """
        Get the identity key pair for end-to-end encryption.

        Returns:
            Dictionary containing public and private identity keys
        """
        try:
            # This would typically retrieve from secure storage
            if not hasattr(self, '_identity_key_pair'):
                raise PymeowError("Identity key pair not initialized")

            return {
                'public': self._identity_key_pair['public'],
                'private': self._identity_key_pair['private']
            }

        except Exception as e:
            logger.error(f"Error getting identity key pair: {e}", exc_info=True)
            raise PymeowError(f"Failed to get identity key pair: {e}") from e

    # Media Message Handler

    async def start(self):
        """Start the message queue processor."""
        if self._message_queue_task is None or self._message_queue_task.done():
            self._message_queue_task = asyncio.create_task(self._process_message_queue())

    async def stop(self):
        """Stop the message queue processor and clean up."""
        if self._message_queue_task and not self._message_queue_task.done():
            self._message_queue_task.cancel()
            try:
                await self._message_queue_task
            except asyncio.CancelledError:
                pass
        self._message_queue_task = None

    # Message queue processing is handled by _process_message_queue above

    async def _send_with_retry(self, message_node: ProtocolNode, max_retries: int = 3) -> Dict[str, Any]:
        """
        Send a message with retry logic, exponential backoff, and jitter.

        This method implements a robust message sending mechanism with the following features:
        - Exponential backoff with jitter to prevent thundering herd
        - Idempotency keys for deduplication
        - Detailed status tracking and logging
        - Configurable retry policies
        - Message state management

        Args:
            message_node: The message node to send
            max_retries: Maximum number of retry attempts (default: 3)

        Returns:
            Dictionary containing:
            - status: Delivery status ('delivered', 'failed')
            - message_id: The final message ID used
            - attempts: Number of attempts made
            - timestamp: Unix timestamp of final status
            - receipt: Delivery receipt if successful

        Raises:
            PymeowError: If all retry attempts fail or an unrecoverable error occurs
        """
        message_id = message_node.attrs.get('id', self._generate_message_id())
        message_node.attrs['id'] = message_id

        base_delay = 1.0  # Start with 1 second delay
        retry_count = 0
        last_error = None
        last_status = 'pending'

        # Generate a unique idempotency key for this message
        idempotency_key = f"{message_id}_{int(time.time())}"

        try:
            while retry_count <= max_retries:
                try:
                    # Create a future to track this message
                    future = asyncio.Future()
                    self._pending_messages[message_id] = future

                    # Update status and log
                    status = 'retry' if retry_count > 0 else 'initial'
                    last_status = status
                    logger.info(f"Sending message {message_id} ({status} attempt {retry_count + 1}/{max_retries + 1})")

                    # Add idempotency key to message attributes
                    if 'idempotency-key' not in message_node.attrs:
                        message_node.attrs['idempotency-key'] = idempotency_key

                    # Send the message
                    await self._send_node(message_node)

                    # Wait for delivery receipt with timeout
                    try:
                        receipt = await asyncio.wait_for(future, timeout=30.0)
                        last_status = 'delivered'

                        # Log successful delivery
                        logger.info(f"Message {message_id} delivered after {retry_count + 1} attempts")

                        return {
                            'status': 'delivered',
                            'message_id': message_id,
                            'attempts': retry_count + 1,
                            'timestamp': int(time.time()),
                            'receipt': receipt
                        }

                    except asyncio.TimeoutError:
                        raise PymeowError(f"Message {message_id} delivery timed out")

                except Exception as e:
                    last_error = e
                    if retry_count == max_retries:
                        break

                    # Calculate exponential backoff with jitter
                    delay = min(base_delay * (2 ** retry_count), 30.0)  # Cap at 30 seconds
                    jitter = random.uniform(0.8, 1.2)  # Add ±20% jitter
                    sleep_time = delay * jitter

                    logger.warning(
                        f"Failed to send message {message_id} (attempt {retry_count + 1}/{max_retries + 1}): {e}. "
                        f"Retrying in {sleep_time:.1f}s..."
                    )

                    # Update status and wait before retry
                    last_status = 'retrying'
                    await asyncio.sleep(sleep_time)
                    retry_count += 1

                    # Update message ID for retry to avoid duplicate detection
                    new_message_id = self._generate_message_id()
                    message_node.attrs['id'] = new_message_id
                    message_id = new_message_id

                finally:
                    # Clean up pending message future
                    if message_id in self._pending_messages:
                        del self._pending_messages[message_id]

            # All retries failed
            error_msg = f"Failed to send message after {max_retries + 1} attempts"
            logger.error(f"{error_msg}: {last_error}", exc_info=True)

            # Update final status
            last_status = 'failed'

            raise PymeowError(f"{error_msg}: {last_error}") from last_error

        except Exception as e:
            # Log any unexpected errors
            logger.error(f"Unexpected error in _send_with_retry: {e}", exc_info=True)
            raise

    async def _enqueue_message(self, message_node: ProtocolNode) -> str:
        """
        Add a message to the send queue with retry support.

        Args:
            message_node: The message node to send

        Returns:
            The message ID

        Note:
            This is a wrapper around _send_with_retry for backward compatibility
        """
        result = await self._send_with_retry(message_node)
        return result['message_id']

    def add_delivery_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Add a handler for message delivery receipts.

        Args:
            handler: Function that takes a delivery receipt dict
        """
        self._delivery_handlers.append(handler)

    def remove_delivery_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Remove a delivery receipt handler.

        Args:
            handler: Handler function to remove
        """
        try:
            self._delivery_handlers.remove(handler)
        except ValueError:
            pass

    def add_read_receipt_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Add a handler for read receipts.

        Args:
            handler: Function that takes a read receipt dict
        """
        self._read_receipt_handlers.append(handler)

    def remove_read_receipt_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Remove a read receipt handler.

        Args:
            handler: Handler function to remove
        """
        try:
            self._read_receipt_handlers.remove(handler)
        except ValueError:
            pass

    async def _handle_message_status_update(self, message_id: str, status: str, error: Optional[str] = None):
        """Handle message status updates and retry logic.

        Args:
            message_id: The ID of the message
            status: The new status of the message
            error: Optional error message if the status is an error
        """
        try:
            # Update message status in the store
            if self._message_store:
                await self._message_store.update_message_status(
                    message_id=message_id,
                    status=status,
                    error=error,
                    timestamp=int(time.time() * 1000)
                )

            # If message failed and we should retry, add it to the retry queue
            if status == 'error' and hasattr(self, '_message_queue') and self._message_queue:
                try:
                    # Get the message details from the store
                    message = await self._message_store.get_message(message_id)
                    if message and message.retry_count < getattr(message, 'max_retries', 3):
                        # Create a new message node for retry
                        message_node = ProtocolNode(
                            tag='message',
                            attrs={
                                'id': message_id,
                                'to': message.to_jid,
                                'type': message.message_type
                            },
                            content=[
                                ProtocolNode('body', content=message.content)
                            ]
                        )

                        # Add to message queue for processing with a new future
                        future = asyncio.Future()
                        await self._message_queue.put((message_id, message_node, future))

                        logger.info(f"Scheduled retry {message.retry_count + 1} for message {message_id}")
                except Exception as e:
                    logger.error(f"Error scheduling retry for message {message_id}: {e}", exc_info=True)

            # Dispatch status update event
            await self._dispatch_event('message_status', {
                'message_id': message_id,
                'status': status,
                'error': error,
                'timestamp': int(time.time() * 1000)
            })

        except Exception as e:
            logger.error(f"Error handling message status update for {message_id}: {e}", exc_info=True)

    async def _handle_receipt(self, receipt_node: ProtocolNode):
        """Handle a message receipt (delivered, read, etc.).

        This method updates the message store with the latest status when receipts are received.
        """
        try:
            receipt_type = receipt_node.attrs.get('type')
            message_ids = receipt_node.attrs.get('id', '').split(',')

            if not message_ids:
                return

            from_jid = receipt_node.attrs.get('from')
            recipient_jid = receipt_node.attrs.get('recipient')
            timestamp = int(receipt_node.attrs.get('t', '0'))

            # Map receipt types to message statuses
            status_map = {
                'delivery': 'delivered',
                'read': 'read',
                'played': 'played',
                'server': 'server_ack',
                'sender': 'sender_ack',
                'inactive': 'inactive',
                'failed': 'failed'
            }

            status = status_map.get(receipt_type, 'received')

            # Update message status in the store for each message ID
            if self._message_store:
                for msg_id in message_ids:
                    if msg_id:  # Skip empty message IDs
                        try:
                            await self._message_store.update_message_status(
                                message_id=msg_id,
                                status=status,
                                timestamp=timestamp or int(time.time() * 1000)
                            )
                        except Exception as e:
                            logger.error(f"Failed to update status for message {msg_id}: {e}", exc_info=True)

            receipt = {
                'type': receipt_type,
                'status': status,
                'message_ids': [msg_id for msg_id in message_ids if msg_id],  # Filter out empty IDs
                'from_jid': from_jid,
                'recipient_jid': recipient_jid,
                'timestamp': timestamp
            }

            # Dispatch receipt event
            await self._dispatch_event('receipt', receipt)

            # Update pending message futures
            for msg_id in message_ids:
                if not msg_id:
                    continue

                if msg_id in self._pending_messages and not self._pending_messages[msg_id].done():
                    self._pending_messages[msg_id].set_result(receipt)

            # Call appropriate handlers
            if receipt_type == 'delivery':
                for handler in self._delivery_handlers:
                    try:
                        handler(receipt)
                    except Exception as e:
                        logger.error(f"Error in delivery handler: {e}", exc_info=True)

            elif receipt_type == 'read':
                for handler in self._read_receipt_handlers:
                    try:
                        handler(receipt)
                    except Exception as e:
                        logger.error(f"Error in read receipt handler: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error handling receipt: {e}", exc_info=True)

    # send_message implementation is defined above with more comprehensive features

    # mark_messages_read implementation is defined below with more comprehensive features

    # Media Message Handler

    # Message History and Search

    async def _query_message_history(self, chat_jid: str, count: int = 50, before: str = None) -> List[Dict[str, Any]]:
        """
        Get message history for a chat.

        Args:
            chat_jid: The chat JID to get history for
            count: Number of messages to retrieve (1-1000)
            before: Message ID to get messages before (for pagination)

        Returns:
            List of message dictionaries
        """
        try:
            # Ensure count is within bounds
            count = max(1, min(1000, count))

            # Build query attributes
            query_attrs = {
                'count': str(count),
                'type': 'chat',
                'owner': 'false',
                'index': '0',
                'jid': chat_jid
            }

            if before:
                query_attrs['before'] = before

            # Create query node
            query_node = ProtocolNode(
                tag='query',
                attrs=query_attrs
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:m'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_message_list(response)

        except Exception as e:
            logger.error(f"Error getting message history: {e}", exc_info=True)
            raise PymeowError(f"Failed to get message history: {e}") from e

    async def search_messages(self, query: str, in_chat: str = None,
                             max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Search messages matching the query.

        Args:
            query: Search query string
            in_chat: Optional chat JID to search within
            max_results: Maximum number of results to return (1-1000)

        Returns:
            List of matching messages
        """
        try:
            # Ensure max_results is within bounds
            max_results = max(1, min(1000, max_results))

            # Build search query
            search_attrs = {
                'query': query,
                'count': str(max_results),
                'index': '0',
                'type': 'all'  # Can be 'all', 'unread', 'contacts', etc.
            }

            if in_chat:
                search_attrs['in'] = 'chat:' + in_chat

            search_node = ProtocolNode(
                tag='search',
                attrs=search_attrs
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:search'
                },
                content=[search_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_search_results(response)

        except Exception as e:
            logger.error(f"Error searching messages: {e}", exc_info=True)
            raise PymeowError(f"Failed to search messages: {e}") from e

    def _parse_search_results(self, response_node) -> List[Dict[str, Any]]:
        """Parse search results from a response node."""
        results = []

        # Handle different result types
        for result_type in ['messages', 'contacts', 'groups']:
            result_nodes = response_node.find_all(result_type)
            if not result_nodes:
                continue

            # For each matching node
            for result_node in result_nodes:

                for item in result_node.find_all('item'):
                    try:
                        result = {
                            'type': result_type[:-1],  # Convert 'messages' to 'message', etc.
                            'score': float(item.attrs.get('score', '0')),
                            'data': {}
                        }

                        # Parse message results
                        if result['type'] == 'message':
                            msg_node = item.find('message')
                            if msg_node:
                                result['data'] = {
                                    'id': msg_node.attrs.get('id'),
                                    'from': msg_node.attrs.get('from'),
                                    'to': msg_node.attrs.get('to'),
                                    'timestamp': int(msg_node.attrs.get('t', '0')),
                                    'content': msg_node.content
                                }

                        # Parse contact results
                        elif result['type'] == 'contact':
                            result['data'] = {
                                'jid': item.attrs.get('jid'),
                                'name': item.attrs.get('name'),
                                'notify': item.attrs.get('notify')
                            }

                        # Parse group results
                        elif result['type'] == 'group':
                            result['data'] = {
                                'jid': item.attrs.get('jid'),
                                'subject': item.attrs.get('subject'),
                                'owner': item.attrs.get('owner')
                            }

                        results.append(result)

                    except Exception as e:
                        logger.warning(f"Error parsing search result: {e}", exc_info=True)

        return sorted(results, key=lambda x: x['score'], reverse=True)

    async def get_message_by_id(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific message by its ID.

        Args:
            message_id: The message ID to look up

        Returns:
            Message dictionary or None if not found
        """
        try:
            query_node = ProtocolNode(
                tag='query',
                attrs={
                    'type': 'message',
                    'id': message_id
                }
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:m'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            messages = self._parse_message_list(response)
            return messages[0] if messages else None

        except Exception as e:
            logger.error(f"Error getting message by ID: {e}", exc_info=True)
            raise PymeowError(f"Failed to get message: {e}") from e

    # Media Message Handler

    # Message Reactions and Replies

    async def get_reaction_senders(self, message_id: str, emoji: str) -> List[str]:
        """
        Get all users who reacted with a specific emoji to a message.

        Args:
            message_id: The ID of the message
            emoji: The emoji to filter by

        Returns:
            List of JIDs of users who reacted with the emoji
        """
        if not hasattr(self, '_message_store') or not self._message_store:
            return []

        return await self._message_store.get_reaction_senders(message_id, emoji)

    async def get_reaction_summary(self, message_id: str, chat_jid: str) -> Dict[str, Dict[str, Any]]:
        """
        Get a summary of reactions for a message.

        Args:
            message_id: The ID of the message
            chat_jid: The JID of the chat containing the message

        Returns:
            Dictionary with emoji as keys and reaction details as values:
            {
                '👍': {
                    'count': 3,
                    'senders': ['user1@s.whatsapp.net', 'user2@s.whatsapp.net'],
                    'last_reacted': 1620000000
                },
                ...
            }
        """
        reactions = await self.get_message_reactions(message_id, chat_jid)

        summary = {}
        for reaction in reactions:
            emoji = reaction['emoji']
            if emoji not in summary:
                summary[emoji] = {
                    'count': 0,
                    'senders': [],
                    'last_reacted': 0
                }

            summary[emoji]['count'] += 1
            summary[emoji]['senders'].append(reaction['sender_jid'])
            if reaction['timestamp'] > summary[emoji]['last_reacted']:
                summary[emoji]['last_reacted'] = reaction['timestamp']

        return summary

    async def send_reply(self, to_message_id: str, chat_jid: str,
                         content: str, quoted_message: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send a reply to a message.

        Args:
            to_message_id: The ID of the message to reply to
            chat_jid: The JID of the chat
            content: The reply content
            quoted_message: Optional quoted message data (if not provided, will be fetched)

        Returns:
            Dictionary with message status
        """
        try:
            if not quoted_message:
                # Fetch the message being replied to
                quoted_message = await self.get_message_by_id(to_message_id)
                if not quoted_message:
                    raise PymeowError(f"Message {to_message_id} not found")

            # Create quoted message node
            quoted_node = ProtocolNode(
                tag='quoted',
                attrs={
                    'from': quoted_message.get('from', ''),
                    'id': to_message_id,
                    't': str(quoted_message.get('timestamp', int(time.time()))),
                    'participant': quoted_message.get('participant', ''),
                    'type': quoted_message.get('type', 'text')
                }
            )

            # Add quoted content if available
            if 'content' in quoted_message:
                quoted_node.content = quoted_message['content']

            # Create message node
            message_node = ProtocolNode(
                tag='message',
                attrs={
                    'id': self._generate_message_id(),
                    'to': chat_jid,
                    'type': 'text',
                    't': str(int(time.time()))
                },
                content=[
                    ProtocolNode('body', content=content),
                    quoted_node
                ]
            )

            # Send and wait for delivery
            receipt = await self._enqueue_message(message_node)
            return {
                'status': 'sent',
                'message_id': message_node.attrs['id'],
                'in_reply_to': to_message_id,
                'content': content,
                'timestamp': int(time.time())
            }

        except Exception as e:
            logger.error(f"Error sending reply: {e}", exc_info=True)
            raise PymeowError(f"Failed to send reply: {e}") from e

    async def get_message_reactions(self, message_id: str, chat_jid: str) -> List[Dict[str, Any]]:
        """
        Get reactions for a message.

        Args:
            message_id: The message ID to get reactions for
            chat_jid: The JID of the chat containing the message

        Returns:
            List of reactions
        """
        try:
            query_node = ProtocolNode(
                tag='reactions',
                attrs={
                    'id': message_id,
                    'jid': chat_jid
                }
            )

            iq_id = self._generate_message_id()
            iq_node = ProtocolNode(
                tag='iq',
                attrs={
                    'id': iq_id,
                    'to': 's.whatsapp.net',
                    'type': 'get',
                    'xmlns': 'w:reactions'
                },
                content=[query_node]
            )

            response = await self._send_iq_and_wait(iq_node, iq_id)
            return self._parse_reactions(response)

        except Exception as e:
            logger.error(f"Error getting message reactions: {e}", exc_info=True)
            raise PymeowError(f"Failed to get message reactions: {e}") from e

    def _parse_reactions(self, response_node) -> List[Dict[str, Any]]:
        """Parse reactions from a response node."""
        reactions = []

        for reaction_node in response_node.find_all('reaction'):
            try:
                reaction = {
                    'sender_jid': reaction_node.attrs.get('sender_jid', ''),
                    'timestamp': int(reaction_node.attrs.get('t', '0')),
                    'emoji': reaction_node.content or ''
                }
                reactions.append(reaction)
            except Exception as e:
                logger.warning(f"Error parsing reaction: {e}", exc_info=True)

        return reactions

    # Message Editing and Forwarding

    async def edit_message(self, message_id: str, chat_jid: str, new_content: str) -> Dict[str, Any]:
        """
        Edit an existing message.

        Args:
            message_id: The ID of the message to edit
            chat_jid: The JID of the chat containing the message
            new_content: The new content for the message

        Returns:
            Dictionary with edit status
        """
        try:
            # Create edit node
            edit_node = ProtocolNode(
                tag='edit',
                attrs={
                    'id': message_id,
                    't': str(int(time.time()))
                },
                content=new_content
            )

            # Create message node
            message_node = ProtocolNode(
                tag='message',
                attrs={
                    'id': self._generate_message_id(),
                    'to': chat_jid,
                    'type': 'text',
                    't': str(int(time.time())),
                    'edit': '1'  # Indicates this is an edit
                },
                content=[edit_node]
            )

            # Send and wait for delivery
            receipt = await self._enqueue_message(message_node)
            return {
                'status': 'edited',
                'original_message_id': message_id,
                'new_message_id': message_node.attrs['id'],
                'content': new_content,
                'timestamp': int(time.time())
            }

        except Exception as e:
            logger.error(f"Error editing message: {e}", exc_info=True)
            raise PymeowError(f"Failed to edit message: {e}") from e

    # Disappearing Messages

    async def set_disappearing_messages(
        self,
        chat_jid: str,
        duration_seconds: int,
        is_ephemeral: bool = False
    ) -> Dict[str, Any]:
        """
        Enable or update disappearing messages for a chat.

        Args:
            chat_jid: The JID of the chat to update
            duration_seconds: Duration in seconds (0 to disable)
            is_ephemeral: Whether to use view-once messages

        Returns:
            A dictionary containing:
            - 'status': 'success' or 'error'
            - 'duration_seconds': The set duration in seconds
            - 'enabled': Whether disappearing messages are now enabled
            - 'is_ephemeral': Whether view-once is enabled

        Raises:
            PymeowError: If there's an error setting the disappearing messages
        """
        try:
            # Validate the duration
            if not DisappearingMessageManager.validate_duration(duration_seconds):
                raise DisappearingMessageError(
                    f"Invalid duration: {duration_seconds}. "
                    f"Must be one of: {list(DisappearingMessageManager.VALID_DURATIONS.values())}"
                )

            # Create the appropriate node based on chat type
            is_group = "@g" in chat_jid
            
            if is_group:
                # For group chats, use the group protocol
                node = ProtocolNode(
                    tag="group",
                    attrs={
                        "id": self._generate_message_id(),
                        "type": "set",
                        "xmlns": "w:disappearing_mode"
                    },
                    content=[
                        ProtocolNode(
                            "disappearing_mode",
                            {"duration": str(duration_seconds)}
                        )
                    ]
                )
                
                if is_ephemeral:
                    node.content.append(ProtocolNode("ephemeral", {"value": "1"}))
                
                # Send the group protocol message
                await self._send_structured_node(
                    to=chat_jid,
                    node=node,
                    expect_response=True
                )
            else:
                # For individual chats, use a regular message with ephemeral settings
                message_node = ProtocolNode(
                    tag="message",
                    attrs={
                        "id": self._generate_message_id(),
                        "to": chat_jid,
                        "type": "chat"
                    },
                    content=[
                        ProtocolNode(
                            "protocol",
                            {
                                "type": "ephemeral_setting",
                                "expiration": str(duration_seconds)
                            }
                        )
                    ]
                )
                
                # Send the message
                await self._enqueue_message(message_node)

            # Update local cache if available
            if hasattr(self, '_message_store') and self._message_store:
                await self._message_store.update_chat_settings(
                    chat_jid,
                    {
                        'disappearing_messages': {
                            'duration': duration_seconds,
                            'is_ephemeral': is_ephemeral,
                            'enabled': duration_seconds > 0
                        }
                    }
                )

            return {
                'status': 'success',
                'duration_seconds': duration_seconds,
                'enabled': duration_seconds > 0,
                'is_ephemeral': is_ephemeral
            }

        except Exception as e:
            logger.error(f"Error setting disappearing messages: {e}", exc_info=True)
            raise PymeowError(f"Failed to set disappearing messages: {e}") from e

    async def get_disappearing_messages(self, chat_jid: str) -> Dict[str, Any]:
        """
        Get the current disappearing messages settings for a chat.

        Args:
            chat_jid: The JID of the chat to get settings for

        Returns:
            A dictionary containing:
            - 'duration_seconds': The current duration in seconds (0 if disabled)
            - 'is_ephemeral': Whether view-once messages are enabled
            - 'enabled': Whether disappearing messages are enabled

        Raises:
            PymeowError: If there's an error getting the settings
        """
        try:
            # Create a node to request disappearing messages settings
            node = ProtocolNode(
                tag="group",
                attrs={
                    "id": self._generate_message_id(),
                    "type": "get",
                    "xmlns": "w:disappearing_mode"
                }
            )

            # Send the request and wait for the response
            response = await self._send_structured_node(
                to=chat_jid,
                node=node,
                expect_response=True
            )

            if not response or not hasattr(response, 'content'):
                raise PymeowError("Invalid response from server")

            # Parse the response
            duration = 0
            is_ephemeral = False
            enabled = False

            for child in response.content:
                if not isinstance(child, ProtocolNode):
                    continue
                
                if child.tag == "disappearing_mode":
                    duration_attr = child.attrs.get("duration")
                    if duration_attr and duration_attr.isdigit():
                        duration = int(duration_attr)
                        enabled = duration > 0
                elif child.tag == "ephemeral" and child.attrs.get("value") == "1":
                    is_ephemeral = True

            return {
                'duration_seconds': duration,
                'is_ephemeral': is_ephemeral,
                'enabled': enabled
            }

        except Exception as e:
            logger.error(f"Error getting disappearing messages settings: {e}", exc_info=True)
            raise PymeowError(f"Failed to get disappearing messages settings: {e}") from e

