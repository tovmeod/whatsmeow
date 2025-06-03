"""
WhatsApp Web client implementation.

Port of whatsmeow/client.go
"""
import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union, TypeVar, Generic, Awaitable
from urllib.parse import urlparse

from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from .generated.waWa6 import WAWebProtobufsWa6_pb2
from .generated.waWeb import WAWebProtobufsWeb_pb2
from .generated.waWeb import WAWebProtobufsWeb_pb2 as waWeb_pb2
from .generated.waCert import WACert_pb2
from .mediaconn import MediaConnMixin
from .pair import handle_iq

from .socket.framesocket import FrameSocket
from .socket.noisesocket import NoiseSocket
from .socket.noisehandshake import NoiseHandshake
from .binary.node import Node, Attrs
from .store import Device
from .types import message
# Types module is now ported
from .types.events import Disconnected, QR, Message, PrivacySettingsEvent
from .types.jid import JID
from .types.presence import Presence, ChatPresence, ChatPresenceMedia
from .exceptions import NoPushNameError, NoPrivacyTokenError, ElementMissingError
from .privacysettings import PrivacySettings, PrivacySettingType, PrivacySetting
from .push import PushConfig
from .util.keys.keypair import KeyPair
from .appstate import Processor

# Type for event handlers
EventHandler = Callable[[Any], Awaitable[None]]

# Constants
HANDLER_QUEUE_SIZE = 2048


@dataclass
class WrappedEventHandler:
    """Wrapper for event handlers with unique IDs."""
    fn: EventHandler
    id: int


@dataclass
class DeviceCache:
    """Cache for device information."""
    devices: List[JID] = field(default_factory=list)
    dhash: str = ""


@dataclass
class GroupMetaCache:
    """Cache for group metadata."""
    addressing_mode: int = 0
    community_announcement_group: bool = False
    members: List[JID] = field(default_factory=list)


@dataclass
class MessengerConfig:
    """Configuration for Messenger (non-WhatsApp) clients."""
    user_agent: str
    base_url: str
    websocket_url: str


@dataclass
class SetProxyOptions:
    """Options for setting a proxy."""
    no_websocket: bool = False
    no_media: bool = False

logger = logging.getLogger(__name__)

class Client(MediaConnMixin):
    """Client for WhatsApp Web API.

    This client provides functionality to connect to and interact with the WhatsApp web API.
    It handles authentication, message sending/receiving, and other WhatsApp features.
    """

    def __init__(self, device_store: Device):
        """Initialize a new WhatsApp web client.

        Args:
            device_store: The device store to use for storing session data
            logger: Optional logger to use for logging. If None, a no-op logger will be used.
        """
        super().__init__()
        # Generate a unique ID prefix
        unique_id_prefix = bytes([random.randint(0, 255), random.randint(0, 255)])

        self.store = device_store
        self.recv_log = logging.getLogger(f"{logger.name}.Recv")
        self.send_log = logging.getLogger(f"{logger.name}.Send")

        # Socket-related fields
        self.socket = None
        self.socket_lock = asyncio.Lock()
        self.socket_wait = asyncio.Event()
        self.ws_dialer = None

        # State flags
        self._is_logged_in = False
        self._expected_disconnect = False
        self.enable_auto_reconnect = True
        self.initial_auto_reconnect = False
        self.last_successful_connect = None
        self.auto_reconnect_errors = 0
        self.auto_reconnect_hook = None
        self.synchronous_ack = False
        self.enable_decrypted_event_buffer = False
        self.last_decrypted_buffer_clear = None

        self.disable_login_auto_reconnect = False

        self.send_active_receipts = 0

        # App state
        self.emit_app_state_events_on_full_sync = False

        self.automatic_message_rerequest_from_phone = False
        self.pending_phone_rerequests = {}
        self.pending_phone_rerequests_lock = asyncio.Lock()

        self.app_state_proc = Processor(device_store, logger.getChild("AppState"))
        self.app_state_sync_lock = asyncio.Lock()

        self.history_sync_notifications = asyncio.Queue(32)
        self.history_sync_handler_started = False

        self.upload_pre_keys_lock = asyncio.Lock()
        self.last_pre_key_upload = None

        # Import JID here to avoid circular imports
        from .types import JID
        self.server_jid = JID.server_jid()

        self.media_conn_cache = None
        self.media_conn_lock = asyncio.Lock()

        # Response handling
        self.response_waiters = {}
        self.response_waiters_lock = asyncio.Lock()

        # Event handling
        self.node_handlers = {}
        self.handler_queue = asyncio.Queue(HANDLER_QUEUE_SIZE)
        self.event_handlers = []
        self.event_handlers_lock = asyncio.Lock()

        # Message handling
        self.message_retries = {}
        self.message_retries_lock = asyncio.Lock()

        self.incoming_retry_request_counter = {}
        self.incoming_retry_request_counter_lock = asyncio.Lock()

        self.app_state_key_requests = {}
        self.app_state_key_requests_lock = asyncio.Lock()

        self.message_send_lock = asyncio.Lock()

        self._privacy_settings_cache: Optional[PrivacySettings] = None
        self._privacy_cache_lock = asyncio.Lock()

        # Caches
        self.group_cache = {}
        self.group_cache_lock = asyncio.Lock()
        self.user_devices_cache = {}
        self.user_devices_cache_lock = asyncio.Lock()

        self.recent_messages_map = {}
        self.recent_messages_list = []
        self.recent_messages_ptr = 0
        self.recent_messages_lock = asyncio.Lock()

        self.session_recreate_history = {}
        self.session_recreate_history_lock = asyncio.Lock()

        # Callbacks
        # pre_retry_callback signature: Callable[[receipt, message_id: str, retry_count: int, message], bool]
        # Return True to proceed with retry, False to cancel
        self.pre_retry_callback = None
        self.pre_pair_callback = None
        self.get_client_payload = None

        # Settings
        self.auto_trust_identity = True
        self.error_on_subscribe_presence_without_token = False

        self.phone_linking_cache = None

        self.unique_id = f"{unique_id_prefix[0]}.{unique_id_prefix[1]}-"
        self.id_counter = 0

        # HTTP and proxy settings
        self.proxy = None
        self.socks_proxy = None
        self.proxy_only_login = False
        self.http = None

        # Messenger config (for non-WhatsApp clients)
        self.messenger_config = None
        self.refresh_cat = None

        # Initialize node handlers
        self._init_node_handlers()

        self._keepalive_task: Optional[asyncio.Task] = None
        self._handler_task: Optional[asyncio.Task] = None

    def _init_node_handlers(self):
        """Initialize the node handlers dictionary."""
        self.node_handlers = {
            "message": self._handle_encrypted_message,
            "appdata": self._handle_encrypted_message,
            "receipt": self._handle_receipt,
            "call": self._handle_call_event,
            "chatstate": self._handle_chat_state,
            "presence": self._handle_presence,
            "notification": self._handle_notification,
            "success": self._handle_connect_success,
            "failure": self._handle_connect_failure,
            "stream:error": self._handle_stream_error,
            "iq": handle_iq,
            "ib": self._handle_ib,
        }

    async def set_proxy_address(self, addr: str, opts: Optional[SetProxyOptions] = None) -> None:
        """Set a proxy address for the client.

        Args:
            addr: The proxy address to use (e.g., "http://proxy.example.com:8080" or "socks5://proxy.example.com:1080")
            opts: Optional proxy options

        Raises:
            ValueError: If the proxy scheme is unsupported
        """
        if not addr:
            self.set_proxy(None, opts)
            return

        parsed = urlparse(addr)
        if parsed.scheme in ("http", "https"):
            # TODO: Implement HTTP proxy support
            self.set_proxy(parsed, opts)
        elif parsed.scheme == "socks5":
            # TODO: Implement SOCKS5 proxy support
            self.set_socks_proxy(parsed, opts)
        else:
            raise ValueError(f"Unsupported proxy scheme {parsed.scheme!r}")

    def set_proxy(self, proxy, opts: Optional[SetProxyOptions] = None):
        """Set an HTTP proxy for the client.

        Args:
            proxy: The proxy to use
            opts: Optional proxy options
        """
        if opts is None:
            opts = SetProxyOptions()

        if not opts.no_websocket:
            self.proxy = proxy
            self.socks_proxy = None

        if not opts.no_media:
            # TODO: Implement HTTP client proxy settings
            pass

    def set_socks_proxy(self, proxy, opts: Optional[SetProxyOptions] = None):
        """Set a SOCKS5 proxy for the client.

        Args:
            proxy: The proxy to use
            opts: Optional proxy options
        """
        if opts is None:
            opts = SetProxyOptions()

        if not opts.no_websocket:
            self.socks_proxy = proxy
            self.proxy = None

        if not opts.no_media:
            # TODO: Implement HTTP client SOCKS proxy settings
            pass

    def toggle_proxy_only_for_login(self, only: bool):
        """Toggle whether the proxy is only used for login.

        Args:
            only: If True, the proxy will only be used for login
        """
        self.proxy_only_login = only

    async def get_socket_wait_chan(self):
        """Get the socket wait event.

        Returns:
            An asyncio.Event that is set when the socket is ready
        """
        async with self.socket_lock:
            return self.socket_wait

    async def close_socket_wait_chan(self):
        """Close and recreate the socket wait event."""
        async with self.socket_lock:
            self.socket_wait.set()
            self.socket_wait = asyncio.Event()

    def get_own_id(self) -> JID:
        """Get the JID of the current device.

        Returns:
            The JID of the current device, or an empty JID if not available
        """
        if self is None:
            return JID.empty()
        return self.store.get_jid()

    def get_message_for_retry(self, sender: JID, chat: JID, message_id: message.MessageID) -> Optional[waE2E_pb2.Message]:
        """Look up a message from the message store when it's not in the recent messages cache.

        Used as fallback when retry.py can't find a message in the recent cache.

        Args:
            sender: The sender JID
            chat: The chat JID
            message_id: The message ID

        Returns:
            The message if found, None if not found
        """
        # This method should look up a message from the message store
        # For now, we'll just return None as we don't have a message store implementation
        # In a real implementation, this would query a database or other storage
        logger.debug(f"Looking up message {message_id} from {sender} in {chat} for retry")
        return None

    async def send_message(self, to: JID, message: Any, peer: bool = False, **kwargs) -> Any:
        """Send a message to a recipient.

        Args:
            to: The recipient JID
            message: The message to send
            peer: Whether to send to a companion device (used for requesting unavailable messages from phone)
            **kwargs: Additional parameters

        Returns:
            The result of the send operation
        """
        # Handle both ways of passing the peer parameter
        if not peer and kwargs.get("peer"):
            peer = True

        logger.debug(f"Sending message to {to}" + (" (peer)" if peer else ""))

        # Implement the actual message sending logic here
        # This would typically involve encryption and sending via the socket

        # For now, just return a placeholder
        return {"status": "sent", "to": str(to), "peer": peer}

    def build_unavailable_message_request(self, chat: JID, sender: JID, message_id: message.MessageID) -> Any:
        """Build a request for an unavailable message.

        Args:
            chat: The chat JID
            sender: The sender JID
            message_id: The message ID

        Returns:
            A message request object
        """
        logger.debug(f"Building request for unavailable message {message_id} from {sender} in {chat}")

        # Build a proper message request for unavailable messages
        # This would typically involve creating a protobuf message

        # For now, return a placeholder message structure
        return {
            "type": "unavailable_message_request",
            "chat": str(chat),
            "sender": str(sender),
            "message_id": message_id
        }

    def get_own_lid(self) -> JID:
        """Get the LID (Local ID) of the current device.

        Returns:
            The LID of the current device, or an empty JID if not available
        """
        if self is None:
            return JID.empty()
        return self.store.get_lid()

    async def wait_for_connection(self, timeout: float) -> bool:
        """Wait for the client to connect and log in.

        Args:
            timeout: The maximum time to wait in seconds

        Returns:
            True if connected and logged in, False if timed out
        """
        if self is None:
            return False

        try:
            async with asyncio.timeout(timeout):
                async with self.socket_lock:
                    while (self.socket is None or
                           not self.socket.is_connected() or
                           not self.is_logged_in()):
                        wait_event = self.socket_wait

                async with self.socket_lock:
                    if (self.socket is None or
                        not self.socket.is_connected() or
                        not self.is_logged_in()):
                        await wait_event.wait()

                return True
        except asyncio.TimeoutError:
            return False

    def set_ws_dialer(self, dialer):
        """Set a custom WebSocket dialer.

        Args:
            dialer: The WebSocket dialer to use
        """
        self.ws_dialer = dialer

    async def connect(self) -> None:
        """Connect to the WhatsApp web websocket.

        After connection, it will either authenticate if there's data in the device store,
        or emit a QR event to set up a new link.

        Returns:
            None

        Raises:
            ValueError: If the connection fails
        """
        try:
            await self._connect()
        except Exception as err:
            # TODO: Check if this is a network error
            is_network_error = True
            if is_network_error and self.initial_auto_reconnect and self.enable_auto_reconnect:
                logger.error("Initial connection failed but reconnecting in background")
                asyncio.create_task(self.dispatch_event(Disconnected()))
                asyncio.create_task(self._auto_reconnect())
                return
            raise

    async def _connect(self) -> None:
        """Internal method to establish a connection to the WhatsApp web websocket.

        Raises:
            ValueError: If the client is nil or already connected
        """
        if self is None:
            raise ValueError("Client is nil")

        async with self.socket_lock:
            if self.socket is not None:
                if not self.socket.is_connected():
                    await self._unlocked_disconnect()
                else:
                    raise ValueError("Already connected")

            self._reset_expected_disconnect()

            # Set up WebSocket dialer
            # TODO: Implement WebSocket dialer configuration

            # Create frame socket
            fs = FrameSocket()
            if self.messenger_config is not None:
                fs.url = self.messenger_config.websocket_url
                fs.http_headers["Origin"] = self.messenger_config.base_url
                fs.http_headers["User-Agent"] = self.messenger_config.user_agent
                fs.http_headers["Cache-Control"] = "no-cache"
                fs.http_headers["Pragma"] = "no-cache"

            # Connect to WebSocket
            try:
                await fs.connect()
            except Exception as e:
                await fs.close(0)
                raise ValueError(f"Failed to connect: {e}")

            # Perform handshake
            try:
                ephemeral_kp = KeyPair.generate()
                await self._do_handshake(fs, ephemeral_kp)
            except Exception as e:
                await fs.close(0)
                raise ValueError(f"Noise handshake failed") from e

            # Start keepalive and handler loops
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())
            self._handler_task = asyncio.create_task(self._handler_queue_loop())


    def is_logged_in(self) -> bool:
        """Check if the client is logged in.

        Returns:
            True if the client is logged in, False otherwise
        """
        return self is not None and self._is_logged_in

    def _expect_disconnect(self) -> None:
        """Mark that a disconnection is expected."""
        self._expected_disconnect = True

    def _reset_expected_disconnect(self) -> None:
        """Reset the expected disconnection flag."""
        self._expected_disconnect = False

    def _is_expected_disconnect(self) -> bool:
        """Check if a disconnection is expected.

        Returns:
            True if a disconnection is expected, False otherwise
        """
        return self._expected_disconnect

    async def _auto_reconnect(self) -> None:
        """Automatically reconnect to the server after a disconnection."""
        if not self.enable_auto_reconnect or self.store.id is None:
            return

        while True:
            auto_reconnect_delay = self.auto_reconnect_errors * 2
            logger.debug(f"Automatically reconnecting after {auto_reconnect_delay} seconds")
            self.auto_reconnect_errors += 1
            await asyncio.sleep(auto_reconnect_delay)

            try:
                await self._connect()
                return
            except ValueError as err:
                if str(err) == "Already connected":
                    logger.debug("Connect() said we're already connected after autoreconnect sleep")
                    return
                else:
                    logger.error(f"Error reconnecting after autoreconnect sleep: {err}")
                    if self.auto_reconnect_hook is not None and not self.auto_reconnect_hook(err):
                        logger.debug("AutoReconnectHook returned false, not reconnecting")
                        return

    def is_connected(self) -> bool:
        """Check if the client is connected to the WhatsApp web websocket.

        Note that this doesn't check if the client is authenticated. See is_logged_in() for that.

        Returns:
            True if the client is connected, False otherwise
        """
        if self is None:
            return False

        # TODO: Implement proper locking
        return self.socket is not None and self.socket.is_connected()

    async def disconnect(self) -> None:
        """Disconnect from the WhatsApp web websocket.

        This will not emit any events. The Disconnected event is only used when the
        connection is closed by the server or a network error.
        """
        if self is None or self.socket is None:
            return

        async with self.socket_lock:
            await self._unlocked_disconnect()

        await self._clear_delayed_message_requests()

    async def _unlocked_disconnect(self) -> None:
        """Disconnect from the WhatsApp web websocket without locking."""
        # Cancel background tasks first
        if self._keepalive_task and not self._keepalive_task.done():
            logger.debug("Cancelling keepalive task")
            self._keepalive_task.cancel()
            self._keepalive_task = None

        if self._handler_task and not self._handler_task.done():
            logger.debug("Cancelling handler task")
            self._handler_task.cancel()
            self._handler_task = None

        if self.socket is not None:
            await self.socket.stop(True)
            self.socket = None
            await self._clear_response_waiters("xmlstreamend")

    async def logout(self) -> None:
        """Log out from WhatsApp and delete the local device store.

        If the logout request fails, the disconnection and local data deletion will not happen either.

        Note that this will not emit any events. The LoggedOut event is only used for external logouts
        (triggered by the user from the main device or by WhatsApp servers).

        Raises:
            ValueError: If the client is nil, using Messenger credentials, or not logged in
        """
        if self is None:
            raise ValueError("Client is nil")
        elif self.messenger_config is not None:
            raise ValueError("Can't logout with Messenger credentials")

        own_id = self.get_own_id()
        if own_id.is_empty():
            raise ValueError("Not logged in")

        # TODO: Implement IQ request
        # _, err = self.send_iq(info_query{
        #     Namespace: "md",
        #     Type: "set",
        #     To: types.ServerJID,
        #     Content: []waBinary.Node{{
        #         Tag: "remove-companion-device",
        #         Attrs: waBinary.Attrs{
        #             "jid": own_id,
        #             "reason": "user_initiated",
        #         },
        #     }},
        # })

        await self.disconnect()
        await self.store.delete()

    def add_event_handler(self, handler: EventHandler) -> int:
        """Register a new async function to receive all events emitted by this client.

        Args:
            handler: The async event handler function

        Returns:
            The event handler ID, which can be passed to remove_event_handler to remove it
        """
        handler_id = random.randint(1, 2**32-1)  # Simple ID generation

        # TODO: Implement proper locking
        self.event_handlers.append(WrappedEventHandler(handler, handler_id))
        return handler_id

    def remove_event_handler(self, handler_id: int) -> bool:
        """Remove a previously registered event handler function.

        Args:
            handler_id: The ID of the handler to remove

        Returns:
            True if the handler was found and removed, False otherwise
        """
        # TODO: Implement proper locking
        for i, handler in enumerate(self.event_handlers):
            if handler.id == handler_id:
                if i == 0:
                    self.event_handlers[0].fn = None
                    self.event_handlers = self.event_handlers[1:]
                    return True
                elif i < len(self.event_handlers) - 1:
                    self.event_handlers[i:] = self.event_handlers[i+1:]

                self.event_handlers[len(self.event_handlers)-1].fn = None
                self.event_handlers = self.event_handlers[:len(self.event_handlers)-1]
                return True

        return False

    def remove_event_handlers(self) -> None:
        """Remove all event handlers that have been registered with add_event_handler."""
        # TODO: Implement proper locking
        self.event_handlers = []

    async def _put_in_handler_queue(self, node: Node) -> None:
        """Put a node in the handler queue, waiting if necessary.

        Args:
            node: The node to put in the queue
        """
        await self.handler_queue.put(node)

    async def _handler_queue_loop(self) -> None:
        """Process nodes from the handler queue."""
        logger.debug("Starting handler queue loop")

        while True:
            try:
                node = await self.handler_queue.get()

                # Process the node in a separate task
                task = asyncio.create_task(self._process_node(node))

                # Wait for the task to complete with a timeout
                try:
                    async with asyncio.timeout(300):  # 5 minutes
                        await task
                except asyncio.TimeoutError:
                    logger.warning(f"Node handling is taking long for {node.xml_string()} - continuing in background")
            except asyncio.CancelledError:
                logger.debug("Closing handler queue loop")
                return

    async def _process_node(self, node: Node) -> None:
        """Process a node from the handler queue.

        Args:
            node: The node to process
        """
        start = time.time()

        try:
            handler = self.node_handlers.get(node.tag)
            if handler:
                await handler(node)
        except Exception as e:
            logger.error(f"Error handling node {node.tag}: {e}")

        duration = time.time() - start
        if duration > 5:
            logger.warning(f"Node handling took {duration:.2f}s for {node.xml_string()}")

    async def _send_node_and_get_data(self, node: Node) -> bytes:
        """Send a node to the server and get the raw data.

        Args:
            node: The node to send

        Returns:
            The raw data sent

        Raises:
            ValueError: If the client is nil or not connected
        """
        if self is None:
            raise ValueError("Client is nil")

        # TODO: Implement proper locking
        if self.socket is None:
            raise ValueError("Not connected")

        try:
            payload = node.marshal()
        except Exception as err:
            raise ValueError(f"Failed to marshal node: {err}")

        self.send_log.debug(f"{node.xml_string()}")
        await self.socket.send_frame(payload)
        return payload

    async def _send_node(self, node: Node) -> None:
        """Send a node to the server.

        Args:
            node: The node to send

        Raises:
            ValueError: If the client is nil or not connected
        """
        await self._send_node_and_get_data(node)

    async def send_iq(self, query: 'InfoQuery') -> Tuple[Node, Optional[Exception]]:
        """Send an info query and wait for response.

        Args:
            query: The info query to send

        Returns:
            A tuple containing the response node and any error that occurred

        Raises:
            ValueError: If the client is nil or not connected
            IQError: If there's an error in the IQ response
            DisconnectedError: If the connection is lost during the request
            ErrIQTimedOut: If the request times out
        """
        from .request import InfoQuery, InfoQueryType, IQError, DisconnectedError, ErrIQTimedOut, is_disconnect_node, parse_iq_error, retry_frame

        # Get the response queue, data, and any error
        res_queue, data, err = await self.send_iq_async_and_get_data(query)
        if err:
            return None, err

        # Wait for the response
        try:
            timeout = query.timeout if query.timeout else 75.0
            ctx = query.context if query.context else asyncio.get_event_loop()

            # Create a task to wait for the response
            resp_task = asyncio.create_task(res_queue.get())

            # Wait for the response or timeout
            done, pending = await asyncio.wait(
                [resp_task],
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel any pending tasks
            for task in pending:
                task.cancel()

            # Check if we got a response
            if resp_task in done:
                res = await resp_task
            else:
                async with self.response_waiters_lock:
                    self.response_waiters.pop(query.id, None)
                return None, ErrIQTimedOut()

            # Check if the response is a disconnect
            if is_disconnect_node(res):
                if query.no_retry:
                    return None, DisconnectedError(action="info query", node=res)

                # Retry the request
                res, err = await retry_frame(self, "info query", query.id, data, res, ctx, timeout)
                if err:
                    return None, err

            # Check if the response is valid
            res_type = res.attributes.get("type")
            if res.tag != "iq" or (res_type != "result" and res_type != "error"):
                return res, IQError(raw_node=res)
            elif res_type == "error":
                return res, parse_iq_error(res)

            return res, None

        except asyncio.CancelledError:
            async with self.response_waiters_lock:
                self.response_waiters.pop(query.id, None)
            raise
        except Exception as e:
            async with self.response_waiters_lock:
                self.response_waiters.pop(query.id, None)
            return None, e

    async def dispatch_event(self, evt: Any) -> None:
        """Dispatch an event to all registered event handlers.

        Args:
            evt: The event to dispatch
        """
        # TODO: Implement proper locking
        for handler in self.event_handlers:
            try:
                await handler.fn(evt)
            except Exception as err:
                logger.exception(f"Event handler panicked while handling a {type(evt).__name__}: {err}")

    async def parse_web_message(self, chat_jid: JID, web_msg: waWeb_pb2.WebMessageInfo) -> Any:
        """Parse a WebMessageInfo object into a Message to match what real-time messages have.

        Args:
            chat_jid: The JID of the chat
            web_msg: The WebMessageInfo to parse

        Returns:
            A Message object

        Raises:
            ValueError: If the chat JID is empty and the remote JID can't be parsed
        """
        # TODO: Implement message parsing
        pass

    async def store_lid_pn_mapping(self, first: JID, second: JID) -> None:
        """Store a mapping between a LID (Local ID) and a PN (Phone Number).

        Args:
            first: The first JID
            second: The second JID
        """
        lid = None
        pn = None

        if first.server == "lid" and second.server == "s.whatsapp.net":
            lid = first
            pn = second
        elif first.server == "s.whatsapp.net" and second.server == "lid":
            lid = second
            pn = first
        else:
            return

        try:
            await self.store.lids.put_lid_mapping(lid, pn)
        except Exception as err:
            logger.error(f"Failed to store LID-PN mapping for {lid} -> {pn}: {err}")

    # Node handler methods
    async def _handle_encrypted_message(self, node: Node) -> None:
        """Handle an encrypted message node.

        Args:
            node: The message node
        """
        # TODO: Implement message handling
        pass

    async def _handle_receipt(self, node: Node) -> None:
        """Handle a receipt node.

        Args:
            node: The receipt node
        """
        # TODO: Implement receipt handling
        pass

    async def _handle_call_event(self, node: Node) -> None:
        """Handle a call event node.

        Args:
            node: The call event node
        """
        from .types.events.call import (
            CallOffer, CallOfferNotice, CallRelayLatency, CallAccept,
            CallPreAccept, CallTransport, CallTerminate, CallReject,
            UnknownCallEvent
        )
        from .types.call import BasicCallMeta, CallRemoteMeta

        # Create a deferred acknowledgment function
        defer_ack = self.maybe_deferred_ack(node)

        try:
            # Check if the node has exactly one child
            children = node.get_children()
            if len(children) != 1:
                await self.dispatch_event(UnknownCallEvent(node=node))
                return

            # Get attributes from the node and its child using AttrGetter
            ag = node.attr_getter()
            child = children[0]
            cag = child.attr_getter()

            # Create basic call metadata
            basic_meta = BasicCallMeta(
                from_jid=ag.jid("from"),
                timestamp=ag.unix_time("t"),
                call_creator=cag.jid("call-creator"),
                call_id=cag.string("call-id")
            )

            # Handle different call event types based on the child tag
            if child.tag == "offer":
                await self.dispatch_event(CallOffer(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version"),
                    data=child
                ))
            elif child.tag == "offer_notice":
                await self.dispatch_event(CallOfferNotice(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    media=cag.string("media"),
                    type=cag.string("type"),
                    data=child
                ))
            elif child.tag == "relaylatency":
                await self.dispatch_event(CallRelayLatency(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    data=child
                ))
            elif child.tag == "accept":
                await self.dispatch_event(CallAccept(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version"),
                    data=child
                ))
            elif child.tag == "preaccept":
                await self.dispatch_event(CallPreAccept(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version"),
                    data=child
                ))
            elif child.tag == "transport":
                await self.dispatch_event(CallTransport(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version"),
                    data=child
                ))
            elif child.tag == "terminate":
                await self.dispatch_event(CallTerminate(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    reason=cag.string("reason"),
                    data=child
                ))
            elif child.tag == "reject":
                await self.dispatch_event(CallReject(
                    from_jid=basic_meta.from_jid,
                    timestamp=basic_meta.timestamp,
                    call_creator=basic_meta.call_creator,
                    call_id=basic_meta.call_id,
                    data=child
                ))
            else:
                await self.dispatch_event(UnknownCallEvent(node=node))
        finally:
            # Call the deferred acknowledgment function
            await defer_ack()

    async def _handle_chat_state(self, node: Node) -> None:
        """Handle a chat state node.

        Args:
            node: The chat state node
        """
        from .presence import handle_chat_state
        await handle_chat_state(self, node)

    async def _handle_presence(self, node: Node) -> None:
        """Handle a presence node.

        Args:
            node: The presence node
        """
        from .presence import handle_presence
        await handle_presence(self, node)

    async def send_presence(self, state: 'Presence') -> None:
        """Update the user's presence status on WhatsApp.

        You should call this at least once after connecting so that the server has your pushname.
        Otherwise, other users will see "-" as the name.

        Args:
            state: The presence state to send

        Raises:
            NoPushNameError: If the client's push name is not set
        """
        from .presence import send_presence
        await send_presence(self, state)

    async def subscribe_presence(self, jid: JID) -> None:
        """Ask the WhatsApp servers to send presence updates of a specific user to this client.

        After subscribing to this event, you should start receiving PresenceEvent for that user
        in normal event handlers.

        Also, it seems that the WhatsApp servers require you to be online to receive presence status
        from other users, so you should mark yourself as online before trying to use this function:

            await client.send_presence(Presence.AVAILABLE)

        Args:
            jid: The JID to subscribe to

        Raises:
            NoPrivacyTokenError: If the client doesn't have a privacy token for the user and
                                ErrorOnSubscribePresenceWithoutToken is set
        """
        from .presence import subscribe_presence
        await subscribe_presence(self, jid)

    async def send_chat_presence(self, jid: JID, state: 'ChatPresence', media: 'ChatPresenceMedia' = None) -> None:
        """Update the user's typing status in a specific chat.

        The media parameter can be set to indicate the user is recording media (like a voice message)
        rather than typing a text message.

        Args:
            jid: The JID of the chat
            state: The chat presence state
            media: The media type (only used with COMPOSING state)
        """
        from .presence import send_chat_presence
        await send_chat_presence(self, jid, state, media)

    async def reject_call(self, call_from: JID, call_id: str) -> None:
        """Reject an incoming call.

        Args:
            call_from: The JID of the caller
            call_id: The ID of the call to reject

        Raises:
            ErrNotLoggedIn: If the client is not logged in
        """
        from .binary.node import Node
        from .exceptions import ErrNotLoggedIn

        own_id = self.get_own_id()
        if own_id.is_empty():
            raise ErrNotLoggedIn()

        # Convert to non-AD JIDs
        own_id = own_id.to_non_ad()
        call_from = call_from.to_non_ad()

        # Send the reject node
        await self.send_node(Node(
            tag="call",
            attributes={
                "id": self.generate_message_id(),
                "from": own_id,
                "to": call_from
            },
            content=[Node(
                tag="reject",
                attributes={
                    "call-id": call_id,
                    "call-creator": call_from,
                    "count": "0"
                }
            )]
        ))

    async def _handle_notification(self, node: Node) -> None:
        """Handle a notification node.

        Args:
            node: The notification node
        """
        # TODO: Implement notification handling
        pass

    async def _handle_connect_success(self, node: Node) -> None:
        """Handle a connection success node.

        Args:
            node: The success node
        """
        # TODO: Implement connect success handling
        pass

    async def _handle_connect_failure(self, node: Node) -> None:
        """Handle a connection failure node.

        Args:
            node: The failure node
        """
        # TODO: Implement connect failure handling
        pass

    async def _handle_stream_error(self, node: Node) -> None:
        """Handle a stream error node.

        Args:
            node: The stream error node
        """
        # TODO: Implement stream error handling
        pass

    async def _handle_ib(self, node: Node) -> None:
        """Handle an IB node.

        Args:
            node: The IB node
        """
        # TODO: Implement IB handling
        pass

    # Helper methods



    async def _receive_response(self, node: Node) -> bool:
        """Process a response node.

        Args:
            node: The response node

        Returns:
            True if the node was handled as a response, False otherwise
        """
        id_attr = node.attributes.get("id")
        if not id_attr or (node.tag != "iq" and node.tag != "ack" and node.tag != "xmlstreamend" and node.tag != "stream:error"):
            return False

        async with self.response_waiters_lock:
            waiter = self.response_waiters.get(id_attr)
            if not waiter:
                return False
            # Remove the waiter from the map to prevent memory leaks
            del self.response_waiters[id_attr]

        try:
            await waiter.put(node)
        except asyncio.QueueFull:
            logger.warning(f"Response queue for {id_attr} is full, dropping response")

        return True

    async def receive_response(self, node: Node) -> bool:
        """Handle a received response and route it to the appropriate waiter.

        Args:
            node: The response node

        Returns:
            True if the node was handled as a response, False otherwise
        """
        return await self._receive_response(node)

    async def send_iq_async_and_get_data(self, query: 'InfoQuery') -> Tuple[asyncio.Queue, bytes, Optional[Exception]]:
        """Send an info query asynchronously and return response queue and data.

        Args:
            query: The info query to send

        Returns:
            A tuple containing the response queue, the raw data sent, and any error that occurred
        """
        from .request import InfoQuery

        if self is None:
            return None, None, ValueError("Client is nil")

        if not query.id:
            # Generate a unique ID for the request
            query.id = f"{self.unique_id}{self.id_counter}"
            self.id_counter += 1

        # Set up a waiter for the response
        response_queue = asyncio.Queue(maxsize=1)
        async with self.response_waiters_lock:
            self.response_waiters[query.id] = response_queue

        # Create the node to send
        attrs = {
            "id": query.id,
            "xmlns": query.namespace,
            "type": query.type.value,
        }

        if query.to:
            attrs["to"] = str(query.to)

        if query.target:
            attrs["target"] = str(query.target)

        node = Node(tag="iq", attributes=attrs, content=query.content)

        # Send the node
        try:
            data = await self._send_node_and_get_data(node)
        except Exception as e:
            async with self.response_waiters_lock:
                self.response_waiters.pop(query.id, None)
            return None, None, e

        return response_queue, data, None

    async def send_iq_async(self, query: 'InfoQuery') -> Tuple[asyncio.Queue, Optional[Exception]]:
        """Send an info query asynchronously.

        Args:
            query: The info query to send

        Returns:
            A tuple containing the response queue and any error that occurred
        """
        queue, _, err = await self.send_iq_async_and_get_data(query)
        return queue, err

    async def _clear_response_waiters(self, reason: str) -> None:
        """Clear all response waiters.

        Args:
            reason: The reason for clearing
        """
        # TODO: Implement response waiter clearing
        pass

    async def _clear_delayed_message_requests(self) -> None:
        """Clear all delayed message requests."""
        # TODO: Implement delayed message request clearing
        pass

    async def get_server_pre_key_count(self, ctx: Any) -> int:
        """Get current pre-key count on server - port of Go's getServerPreKeyCount.

        Args:
            ctx: Context for the request (usually an asyncio event loop)

        Returns:
            int: The number of pre-keys on the server

        Raises:
            ValueError: If there's an error communicating with the server
        """
        from .request import InfoQuery, InfoQueryType

        # Send IQ with namespace="encrypt", type="get", content=[Node(tag="count")]
        resp, err = await self.send_iq(InfoQuery(
            namespace="encrypt",
            type=InfoQueryType.GET,
            to=self.server_jid,
            context=ctx,
            content=[Node(tag="count")]
        ))

        if err:
            raise ValueError(f"Failed to get prekey count: {err}")

        # Parse response and return count value
        count_node = None
        for child in resp.content:
            if isinstance(child, Node) and child.tag == "count":
                count_node = child
                break

        if not count_node:
            raise ValueError("Failed to get prekey count: missing count node in response")

        try:
            count_value = int(count_node.attributes.get("value", "0"))
            return count_value
        except (ValueError, TypeError) as e:
            raise ValueError(f"Failed to parse prekey count: {e}")

    async def upload_pre_keys(self, ctx: Any) -> None:
        """Upload pre-keys to server - port of Go's uploadPreKeys.

        Args:
            ctx: Context for the request (usually an asyncio event loop)

        Raises:
            ValueError: If there's an error communicating with the server
        """
        from .request import InfoQuery, InfoQueryType
        from .prekeys import WANTED_PREKEY_COUNT, pre_key_to_node, pre_keys_to_nodes, DJB_TYPE
        import struct
        import time

        # Acquire lock to prevent concurrent uploads
        async with self.upload_pre_keys_lock:
            # Check if we've uploaded recently (10 minute cooldown)
            if self.last_pre_key_upload is not None:
                if time.time() - self.last_pre_key_upload < 600:  # 10 minutes in seconds
                    # Check server count before uploading
                    try:
                        server_count = await self.get_server_pre_key_count(ctx)
                        if server_count >= WANTED_PREKEY_COUNT:
                            logger.debug("Canceling prekey upload request due to likely race condition")
                            return
                    except Exception as e:
                        logger.error(f"Failed to get server pre-key count: {e}")
                        # Continue with upload anyway

            # Encode registration ID as 4-byte big-endian integer
            registration_id_bytes = struct.pack(">I", self.store.pre_keys.registration_id)

            # Get or generate pre-keys
            try:
                pre_keys = await self.store.pre_keys.get_or_gen_pre_keys(WANTED_PREKEY_COUNT)
                if not pre_keys:
                    logger.error("No pre-keys available for upload")
                    return
            except Exception as e:
                logger.error(f"Failed to get pre-keys to upload: {e}")
                return

            logger.info(f"Uploading {len(pre_keys)} new pre-keys to server")

            # Send IQ with registration ID, type, identity key, pre-key list, and signed pre-key
            try:
                _, err = await self.send_iq(InfoQuery(
                    namespace="encrypt",
                    type=InfoQueryType.SET,
                    to=self.server_jid,
                    context=ctx,
                    content=[
                        Node(tag="registration", content=registration_id_bytes),
                        Node(tag="type", content=bytes([DJB_TYPE])),
                        Node(tag="identity", content=self.store.pre_keys.identity_key),
                        Node(tag="list", content=pre_keys_to_nodes(pre_keys)),
                        pre_key_to_node(self.store.pre_keys.signed_pre_key)
                    ]
                ))

                if err:
                    logger.error(f"Failed to upload pre-keys: {err}")
                    return

                logger.debug("Got response to uploading pre-keys")

                # Mark keys as uploaded
                await self.store.pre_keys.mark_keys_as_uploaded(pre_keys[-1].key_id)

                # Update last upload time
                self.last_pre_key_upload = time.time()

            except Exception as e:
                logger.error(f"Failed to upload pre-keys: {e}")
                return

    async def fetch_pre_keys(self, ctx: Any, users: List['JID']) -> Dict['JID', 'PreKeyResp']:
        """Fetch pre-key bundles for users - port of Go's fetchPreKeys.

        Args:
            ctx: Context for the request (usually an asyncio event loop)
            users: List of user JIDs to fetch pre-keys for

        Returns:
            Dict[JID, PreKeyResp]: Dictionary mapping user JIDs to pre-key responses

        Raises:
            ValueError: If there's an error communicating with the server
        """
        from .request import InfoQuery, InfoQueryType
        from .prekeys import PreKeyResp, node_to_pre_key_bundle

        # Create request nodes for each user
        request_nodes = []
        for user in users:
            request_nodes.append(Node(
                tag="user",
                attributes={
                    "jid": str(user),
                    "reason": "identity"
                }
            ))

        # Send IQ with namespace="encrypt", type="get", content=[Node(tag="key", content=request_nodes)]
        try:
            resp, err = await self.send_iq(InfoQuery(
                namespace="encrypt",
                type=InfoQueryType.GET,
                to=self.server_jid,
                context=ctx,
                content=[Node(
                    tag="key",
                    content=request_nodes
                )]
            ))

            if err:
                raise ValueError(f"Failed to send pre-key request: {err}")
        except Exception as e:
            raise ValueError(f"Failed to send pre-key request: {e}")

        # Check if response is empty
        if not resp.content:
            raise ValueError("Got empty response to pre-key request")

        # Find the list node in the response
        list_node = None
        for child in resp.content:
            if isinstance(child, Node) and child.tag == "list":
                list_node = child
                break

        if not list_node:
            raise ValueError("Missing list node in pre-key response")

        # Parse the response for each user
        result = {}
        for child in list_node.content:
            if not isinstance(child, Node) or child.tag != "user":
                continue

            # Get the JID from the user node
            try:
                from .types import JID
                user_jid = JID.from_string(child.attributes.get("jid", ""))
            except Exception as e:
                logger.warning(f"Failed to parse JID in pre-key response: {e}")
                continue

            # Parse the pre-key bundle or error
            try:
                bundle = node_to_pre_key_bundle(user_jid.device, child)
                result[user_jid] = PreKeyResp(bundle=bundle, error=None)
            except Exception as e:
                result[user_jid] = PreKeyResp(bundle=None, error=e)

        return result

    async def try_fetch_privacy_settings(self, ignore_cache: bool = False) -> Tuple[Optional[PrivacySettings], Optional[Exception]]:
        """Fetches the user's privacy settings, either from the in-memory cache or from the server.

        Args:
            ignore_cache: If True, ignores the cache and fetches from the server.

        Returns:
            A tuple containing the privacy settings and an error (if any).
        """
        if self is None:
            return None, ElementMissingError(tag="client", location="try_fetch_privacy_settings")

        async with self._privacy_cache_lock:
            if self._privacy_settings_cache is not None and not ignore_cache:
                return self._privacy_settings_cache, None

        from .request import InfoQuery, InfoQueryType

        resp, err = await self.send_iq(InfoQuery(
            namespace="privacy",
            type=InfoQueryType.GET,
            to=self.server_jid,
            content=[Node(tag="privacy")]
        ))

        if err:
            return None, err

        privacy_node = None
        for child in resp.content or []:
            if isinstance(child, Node) and child.tag == "privacy":
                privacy_node = child
                break

        if not privacy_node:
            return None, ElementMissingError(tag="privacy", location="response to privacy settings query")

        settings = PrivacySettings()
        self._parse_privacy_settings(privacy_node, settings)

        async with self._privacy_cache_lock:
            self._privacy_settings_cache = settings

        return settings, None

    async def get_privacy_settings(self) -> PrivacySettings:
        """Gets the user's privacy settings. If an error occurs while fetching them,
        the error will be logged, but the method will just return an empty struct.

        Returns:
            The privacy settings.
        """
        if self is None or self.messenger_config is not None:
            return PrivacySettings()

        settings, err = await self.try_fetch_privacy_settings(False)
        if err:
            logger.error(f"Failed to fetch privacy settings: {err}")
            return PrivacySettings()

        return settings

    async def set_privacy_setting(self, name: PrivacySettingType, value: PrivacySetting) -> Tuple[PrivacySettings, Optional[Exception]]:
        """Sets the given privacy setting to the given value.

        The privacy settings will be fetched from the server after the change and the new settings will be returned.
        If an error occurs while fetching the new settings, will return an empty struct.

        Args:
            name: The privacy setting to change.
            value: The new value for the setting.

        Returns:
            A tuple containing the updated privacy settings and an error (if any).
        """
        settings_ptr, err = await self.try_fetch_privacy_settings(False)
        if err:
            return PrivacySettings(), err

        from .request import InfoQuery, InfoQueryType

        _, err = await self.send_iq(InfoQuery(
            namespace="privacy",
            type=InfoQueryType.SET,
            to=self.server_jid,
            content=[Node(
                tag="privacy",
                content=[Node(
                    tag="category",
                    attributes={
                        "name": name,
                        "value": value,
                    }
                )]
            )]
        ))

        if err:
            return PrivacySettings(), err

        settings = settings_ptr

        # Update the local settings object
        if name == PrivacySettingType.GROUP_ADD:
            settings.group_add = value
        elif name == PrivacySettingType.LAST_SEEN:
            settings.last_seen = value
        elif name == PrivacySettingType.STATUS:
            settings.status = value
        elif name == PrivacySettingType.PROFILE:
            settings.profile = value
        elif name == PrivacySettingType.READ_RECEIPTS:
            settings.read_receipts = value
        elif name == PrivacySettingType.ONLINE:
            settings.online = value
        elif name == PrivacySettingType.CALL_ADD:
            settings.call_add = value

        async with self._privacy_cache_lock:
            self._privacy_settings_cache = settings

        return settings, None

    async def set_default_disappearing_timer(self, timer: int) -> Optional[Exception]:
        """Sets the default disappearing message timer.

        Args:
            timer: The timer duration in seconds.

        Returns:
            An error if the operation fails, None otherwise.
        """
        from .request import InfoQuery, InfoQueryType

        _, err = await self.send_iq(InfoQuery(
            namespace="disappearing_mode",
            type=InfoQueryType.SET,
            to=self.server_jid,
            content=[Node(
                tag="disappearing_mode",
                attributes={
                    "duration": str(timer),
                }
            )]
        ))

        return err

    def _parse_privacy_settings(self, privacy_node: Node, settings: PrivacySettings) -> PrivacySettingsEvent:
        """Parses privacy settings from a node.

        Args:
            privacy_node: The node containing privacy settings.
            settings: The settings object to update.

        Returns:
            An event indicating which settings changed.
        """
        evt = PrivacySettingsEvent(new_settings={})

        for child in privacy_node.content or []:
            if not isinstance(child, Node) or child.tag != "category":
                continue

            name = child.attributes.get("name", "")
            value = child.attributes.get("value", "")

            if name == PrivacySettingType.GROUP_ADD:
                settings.group_add = PrivacySetting(value)
                evt.group_add_changed = True
            elif name == PrivacySettingType.LAST_SEEN:
                settings.last_seen = PrivacySetting(value)
                evt.last_seen_changed = True
            elif name == PrivacySettingType.STATUS:
                settings.status = PrivacySetting(value)
                evt.status_changed = True
            elif name == PrivacySettingType.PROFILE:
                settings.profile = PrivacySetting(value)
                evt.profile_changed = True
            elif name == PrivacySettingType.READ_RECEIPTS:
                settings.read_receipts = PrivacySetting(value)
                evt.read_receipts_changed = True
            elif name == PrivacySettingType.ONLINE:
                settings.online = PrivacySetting(value)
                evt.online_changed = True
            elif name == PrivacySettingType.CALL_ADD:
                settings.call_add = PrivacySetting(value)
                evt.call_add_changed = True

        evt.new_settings = settings
        return evt

    async def handle_privacy_settings_notification(self, privacy_node) -> None:
        """Handles privacy settings change notifications.

        Args:
            privacy_node: The node containing the privacy settings notification.
        """
        logger.debug("Parsing privacy settings change notification")

        settings, err = await self.try_fetch_privacy_settings(False)
        if err:
            logger.error(f"Failed to fetch privacy settings when handling change: {err}")
            return

        evt = self._parse_privacy_settings(privacy_node, settings)

        async with self._privacy_cache_lock:
            self._privacy_settings_cache = settings

        await self.dispatch_event(evt)

    async def get_server_push_notification_config(self) -> Optional[Node]:
        """Retrieves server push notification settings."""
        if not self:
            return None

        from .request import InfoQuery, InfoQueryType

        resp, err = await self.send_iq(InfoQuery(
            namespace="urn:xmpp:whatsapp:push",
            type=InfoQueryType.GET,
            to=self.server_jid,
            content=[Node(tag="settings", attributes={})]
        ))

        if err:
            logger.error(f"Failed to get server push notification config: {err}")
            return None

        return resp

    async def register_for_push_notifications(self, pc: PushConfig) -> None:
        """
        Registers a device for push notifications.

        This is generally not necessary for anything. Don't use this if you don't know what you're doing.

        Args:
            pc: The push configuration to register

        Raises:
            ElementMissingError: If the client is nil
            Exception: If there's an error registering for push notifications
        """
        if not self:
            raise ElementMissingError(tag="client", location="register_for_push_notifications")

        from .request import InfoQuery, InfoQueryType

        _, err = await self.send_iq(InfoQuery(
            namespace="urn:xmpp:whatsapp:push",
            type=InfoQueryType.SET,
            to=self.server_jid,
            content=[Node(tag="config", attributes=pc.get_push_config_attrs())]
        ))

        if err:
            raise Exception(f"Failed to register for push notifications: {err}")
