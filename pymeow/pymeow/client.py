"""
WhatsApp Web client implementation.

Port of whatsmeow/client.go
"""
import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
import datetime
from os import urandom
from typing import Any, Callable, List, Optional, Tuple, Awaitable, TYPE_CHECKING, Dict, Set, Coroutine
from urllib.parse import urlparse

import aiohttp

from . import handshake, keepalive, request, retry, connectionevents
from .appstate.keys import Processor
from .binary.unpack import unpack
from .call import handle_call_event
from .connectionevents import handle_ib
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from .generated.waWeb import WAWebProtobufsWeb_pb2 as waWeb_pb2
from .message import handle_encrypted_message
from .notification import handle_notification
from .pair import handle_iq
from .presence import handle_chat_state, handle_presence
from .receipt import handle_receipt

from .socket.framesocket import FrameSocket
from .binary.node import Node, unmarshal, marshal
from .socket.noisesocket import NoiseSocket
from .store.store import Device
from .types import message
from .types.events import Disconnected, PrivacySettingsEvent, events
from .types.jid import JID, EMPTY_JID, HIDDEN_USER_SERVER, DEFAULT_USER_SERVER, NEWSLETTER_SERVER, GROUP_SERVER
from .types.message import AddressingMode, MessageInfo, MessageSource
from .types.presence import Presence, ChatPresence, ChatPresenceMedia
from .exceptions import ElementMissingError, ErrNotLoggedIn, ErrNotConnected, ErrAlreadyConnected
from .privacysettings import PrivacySettings, PrivacySettingType, PrivacySetting
from .push import PushConfig
from .util.keys.keypair import KeyPair

# Type for event handlers
EventHandler = Callable[[Any], Awaitable[None]]

# Constants
HANDLER_QUEUE_SIZE = 2048

if TYPE_CHECKING:
    from .request import InfoQuery, InfoQueryType


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
    addressing_mode: Optional[AddressingMode] = None
    community_announcement_group: bool = False
    members: List[JID] = field(default_factory=list)


@dataclass
class MessengerConfig:
    """Configuration for Messenger (non-WhatsApp) clients."""
    user_agent: str
    base_url: str
    websocket_url: str

logger = logging.getLogger(__name__)

# todo: port sendNodeAndGetData in client.go to send_node_and_get_data
class Client:
    """Client for WhatsApp Web API.

    This client provides functionality to connect to and interact with the WhatsApp web API.
    It handles authentication, message sending/receiving, and other WhatsApp features.
    """

    # The Go struct has two callback function fields that are missing in the Python __init__:
    # GetMessageForRetry func(requester, to types.JID, id types.MessageID) *waE2E.Message
    # GetClientPayload func() *waWa6.ClientPayload
    # These should be added as attributes, initialized to None.
    # TODO: Add GetMessageForRetry callback attribute
    # TODO: Add GetClientPayload callback attribute

    def __init__(self, device_store: Device):
        """Initialize a new WhatsApp web client.

        Args:
            device_store: The device store to use for storing session data
        """
        super().__init__()
        self.store: 'Device' = device_store
        self.recv_log = logging.getLogger(f"{logger.name}.Recv")
        self.send_log = logging.getLogger(f"{logger.name}.Send")

        # Socket-related fields
        self.socket: Optional[NoiseSocket] = None
        self.socket_lock = asyncio.Lock()
        self.socket_wait = asyncio.Event()
        self.ws_dialer: Optional[aiohttp.ClientSession] = None

        # State flags
        self._is_logged_in = False
        self._expected_disconnect = False
        self.enable_auto_reconnect = True
        self.initial_auto_reconnect = False
        self.last_successful_connect: Optional[datetime] = None
        self.auto_reconnect_errors = 0
        self.auto_reconnect_hook: Optional[Callable[[Exception], bool]] = None
        self.synchronous_ack = False
        self.enable_decrypted_event_buffer = False
        self.last_decrypted_buffer_clear: Optional[datetime] = None

        self.disable_login_auto_reconnect = False

        self.send_active_receipts = 0

        # App state
        self.emit_app_state_events_on_full_sync = False

        self.automatic_message_rerequest_from_phone = False
        self.pending_phone_rerequests: Dict[Any, Any] = {}
        self.pending_phone_rerequests_lock = asyncio.Lock()

        self.app_state_proc = Processor(device_store)
        self.app_state_sync_lock = asyncio.Lock()

        # Go: chan *waE2E.HistorySyncNotification (unbuffered or default size) -> Python: asyncio.Queue(32)
        # The buffer size (32) is a behavioral difference from an unbuffered Go channel.
        # Consider asyncio.Queue() for an unbounded queue or asyncio.Queue(1) for closer to unbuffered semantics if backpressure is important.
        # TODO: Type hint for history_sync_notifications queue items
        self.history_sync_notifications = asyncio.Queue(32)
        self.history_sync_handler_started = False

        self.upload_prekeys_lock = asyncio.Lock()
        self.last_pre_key_upload: Optional[datetime] = None

        # Import JID here to avoid circular imports
        from .types import JID
        self.server_jid = JID.server_jid()

        self.media_conn_cache = None # TODO: Type hint for media_conn_cache
        self.media_conn_lock = asyncio.Lock()

        # Response handling
        # TODO: Type hint for response_waiters values (should be asyncio.Queue[Node])
        self.response_waiters: Dict[str, asyncio.Queue[Any]] = {}
        self.response_waiters_lock = asyncio.Lock()

        # Event handling
        # TODO: Type hint for node_handlers values (should be Callable[[Node], Awaitable[None]] or similar)
        self.node_handlers: Dict[str, Callable[[Any], Awaitable[None]]] = {}
        # Go: chan *waBinary.Node (unbuffered or default size) -> Python: asyncio.Queue(HANDLER_QUEUE_SIZE)
        # The buffer size (HANDLER_QUEUE_SIZE=2048) is a behavioral difference from an unbuffered Go channel.
        # Consider asyncio.Queue() for an unbounded queue or asyncio.Queue(1) for closer to unbuffered semantics if backpressure is important.
        # TODO: Type hint for handler_queue queue items
        self.handler_queue: asyncio.Queue[Any] = asyncio.Queue(HANDLER_QUEUE_SIZE)
        self.event_handlers: List[WrappedEventHandler] = []
        self.event_handlers_lock = asyncio.Lock()

        # Message handling
        self.message_retries: Dict[str, int] = {}
        self.message_retries_lock = asyncio.Lock()

        # TODO: Type hint for incoming_retry_request_counter keys
        self.incoming_retry_request_counter: Dict[Any, int] = {}
        self.incoming_retry_request_counter_lock = asyncio.Lock()

        # Go: map[string]time.Time -> Python: Dict[str, datetime] (OK)
        self.app_state_key_requests: Dict[str, datetime] = {}
        self.app_state_key_requests_lock = asyncio.Lock()

        self.message_send_lock = asyncio.Lock()

        self._privacy_settings_cache: Optional[PrivacySettings] = None
        self._privacy_cache_lock = asyncio.Lock()

        # Caches
        # TODO: Type hint for group_cache values
        self.group_cache: Dict[JID, GroupMetaCache] = {}
        self.group_cache_lock = asyncio.Lock()
        # TODO: Type hint for user_devices_cache values
        self.user_devices_cache: Dict[JID, DeviceCache] = {}
        self.user_devices_cache_lock = asyncio.Lock()

        # TODO: Type hint for recent_messages_map keys and values
        self.recent_messages_map: Dict[Any, Any] = {}
        # Go: [recentMessagesSize]recentMessageKey (fixed-size array) -> Python: List[recentMessageKey] (dynamic list)
        # This is a behavioral difference. If fixed size is critical, a different Python structure might be needed.
        # TODO: Type hint for recent_messages_list items
        self.recent_messages_list: List[Any] = []  # Go has a fixed-size array, Python has a dynamic list.
        self.recent_messages_ptr = 0  # Go: int -> Python: int (OK)
        self.recent_messages_lock = asyncio.Lock()

        self.session_recreate_history: Dict[JID, datetime] = {}
        self.session_recreate_history_lock = asyncio.Lock()

        # Callbacks
        # pre_retry_callback signature: Callable[[receipt, message_id: str, retry_count: int, message], bool]
        # Return True to proceed with retry, False to cancel
        # Go: GetMessageForRetry func(...) *waE2E.Message -> Python: Missing attribute
        # TODO: Add self.get_message_for_retry attribute (Optional[Callable[[JID, JID, MessageID], Message]]) = None

        # Go: PreRetryCallback func(...) bool -> Python: Callable[[receipt, message_id: str, retry_count: int, message], bool] (OK)
        # TODO: Type hint for pre_retry_callback arguments
        self.pre_retry_callback: Optional[Callable[[Any, Any, int, Any], bool]] = None

        # Go: PrePairCallback func(...) bool -> Python: Callable[[JID, str, str], bool] (OK)
        # TODO: Type hint for pre_pair_callback arguments
        self.pre_pair_callback: Optional[Callable[[JID, str, str], bool]] = None

        # Go: GetClientPayload func() *waWa6.ClientPayload -> Python: Missing attribute
        # TODO: Add self.get_client_payload attribute (Optional[Callable[[], ClientPayload]]) = None # TODO: Type hint for ClientPayload

        # Settings
        self.auto_trust_identity = True
        self.error_on_subscribe_presence_without_token = False

        self.phone_linking_cache = None # TODO: Type hint for phone_linking_cache

        # Generate a unique ID prefix
        unique_id_prefix = urandom(2)
        self.unique_id = f"{unique_id_prefix[0]}.{unique_id_prefix[1]}-"
        self.id_counter = 0

        self.http: aiohttp.ClientSession = aiohttp.ClientSession(trust_env=True)

        # Messenger config (for non-WhatsApp clients)
        self.messenger_config: Optional[
            MessengerConfig] = None  # Go: *MessengerConfig -> Python: Optional[MessengerConfig] (OK)
        # Go: RefreshCAT func() error -> Python: Callable[[], Optional[Exception]] (OK)
        self.refresh_cat: Optional[Callable[[], Optional[Exception]]] = None

        # Initialize node handlers
        self._init_node_handlers()

        # These are extra attributes in Python, likely for managing async tasks.
        self._keepalive_task: Optional[asyncio.Task] = None
        self._handler_task: Optional[asyncio.Task] = None

        self._background_tasks: Set[asyncio.Task] = set()

    def _init_node_handlers(self):
        """Initialize the node handlers dictionary."""
        self.node_handlers = {
            "message": handle_encrypted_message,
            "appdata": handle_encrypted_message,
            "receipt": handle_receipt,
            "call": handle_call_event,
            "chatstate": handle_chat_state,
            "presence": handle_presence,
            "notification": handle_notification,
            "success": connectionevents.handle_connect_success,
            "failure": connectionevents.handle_connect_failure,
            "stream:error": connectionevents.handle_stream_error,
            "iq": handle_iq,
            "ib": handle_ib,
        }

    def create_task(self, coro: Awaitable[Any]) -> asyncio.Task:
        """
        Create a background task and track it to prevent garbage collection.

        Args:
            coro: The coroutine to run

        Returns:
            The created task
        """
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)

        task.add_done_callback(self._background_tasks.discard)

        return task

    async def get_socket_wait_chan(self) -> asyncio.Event:
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
            return EMPTY_JID
        return self.store.get_jid()

    def get_own_lid(self) -> JID:
        """Get the LID (Local ID) of the current device.

        Returns:
            The LID of the current device, or an empty JID if not available
        """
        if self is None:
            return EMPTY_JID
        return self.store.get_lid()

    async def wait_for_connection(self, timeout: float) -> bool:
        """Wait for the client to connect and log in.

        Args:
            timeout: The maximum time to wait in seconds.

        Returns:
            True if connected and logged in, False if timed out.
        """
        # The `if self is None:` check from the input Python is unidiomatic for instance methods
        # and has been removed. It's assumed `self` is a valid instance.
        # The Go equivalent `if cli == nil` is a check on the receiver itself.

        try:
            async with asyncio.timeout(timeout):  # Overall timeout for the entire operation
                while True:  # Loop until connected or timed out by the context manager
                    async with self.socket_lock:  # Acquire lock to check state
                        # Go: cli.socket == nil || !cli.socket.IsConnected() || !cli.IsLoggedIn()
                        if (self.socket is not None and self.socket.is_connected() and
                            self.is_logged_in()):
                            # Condition met, successfully connected and logged in
                            return True

                        # Condition not met, prepare to wait for a state change
                        wait_event = self.socket_wait

                    # Lock is released here by exiting the `async with self.socket_lock` block

                    # Wait for the socket_wait event to be set, or for the outer timeout
                    # Go: select { case <-ch: case <-timeoutChan: ... }
                    await wait_event.wait()
                    # After waiting (event was set), the loop continues to re-check the condition under lock.
                    # If socket_wait is an asyncio.Event, it might need to be cleared if it's a one-time signal
                    # that should only be processed once per change. However, the Go channel pattern
                    # implies it's set when there's a change, and re-checking is desired.
                    # If `wait_event` is set and the condition is still false, we'll loop and wait again.
                    # This matches the Go behavior where `case <-ch:` leads to re-evaluation.
        except asyncio.TimeoutError:
            # Timeout occurred either during `await wait_event.wait()` or elsewhere within the `async with asyncio.timeout` block.
            return False

    async def connect(self) -> Exception | None:
        """Connect to the WhatsApp web websocket.

        After connection, it will either authenticate if there's data in the device store,
        or emit a QR event to set up a new link.

        Returns:
            None

        Returns:
            Optional[Exception]: None if successful or if background reconnection is
                                 initiated, otherwise the Exception that occurred.
        """
        err = await self._connect()

        if (err is not None and isinstance(err, (aiohttp.ClientConnectionError,
                                                aiohttp.ClientError,
                                                ConnectionError,
                                                OSError,
                                                socket.error,
                                                asyncio.TimeoutError,
                                                aiohttp.ServerTimeoutError,
                                                aiohttp.ClientTimeout))
            and self.initial_auto_reconnect and self.enable_auto_reconnect):
            logger.error("Initial connection failed but reconnecting in background")

            self.create_task(self.dispatch_event(Disconnected()))
            self.create_task(self.auto_reconnect())

            # Go: return nil (meaning the public Connect() call doesn't propagate this specific error)
            return None  # Explicitly return None for clarity

        # Go: return err
        # Python: raise -> Should return the error object
        # If the error was None (success), this returns None.
        # If the error was not None but didn't meet the "reconnect" condition, this returns the error.
        return err

    async def _connect(self) -> Optional[Exception]:
        """Internal method to establish a connection to the WhatsApp web websocket.

        Returns:
            Optional[Exception]: None on success, or an Exception if an error occurred.
        """
        # Go: if cli == nil { return ErrClientIsNil }
        # This check is typically not needed for instance methods in Python,
        # as `self` is guaranteed to be an instance.
        # If `ClientIsNilError` is truly desired, it would be raised by the caller
        # if it tried to call a method on a None client object.

        async with self.socket_lock:  # Go: cli.socketLock.Lock(); defer cli.socketLock.Unlock()
            if self.socket is not None:
                # Go: if !cli.socket.IsConnected() { cli.unlockedDisconnect() }
                if not self.socket.is_connected():
                    await self._unlocked_disconnect()
                else:
                    # Go: return ErrAlreadyConnected
                    return ErrAlreadyConnected()

            self._reset_expected_disconnect()

            # Go: fs := socket.NewFrameSocket(cli.Log.Sub("Socket"), wsDialer)
            # Python: Pass logger and dialer config to FrameSocket constructor
            fs = FrameSocket(dialer=self.ws_dialer)  # todo: check if this is saved, socket needs to be closed

            if self.messenger_config is not None:
                fs.url = self.messenger_config.websocket_url
                fs.http_headers["Origin"] = self.messenger_config.base_url
                fs.http_headers["User-Agent"] = self.messenger_config.user_agent
                fs.http_headers["Cache-Control"] = "no-cache"
                fs.http_headers["Pragma"] = "no-cache"

            # Go: if err := fs.Connect(); err != nil { fs.Close(0); return err }
            try:
                connect_err = await fs.connect()  # Assuming connect returns Optional[Exception]
                if connect_err:
                    await fs.close(0)
                    return connect_err
            except Exception as e_connect:  # Catching exceptions if fs.connect raises them
                await fs.close(0)
                # Return the caught exception directly to match Go's error return
                return ValueError(f"Failed to connect: {e_connect}")

            # Go: else if err = cli.doHandshake(fs, *keys.NewKeyPair()); err != nil { ... }
            # Python: Perform handshake
            ephemeral_kp = KeyPair.generate()
            try:
                # In Go, cli.doHandshake assigns the resulting NoiseSocket to cli.socket.
                # The Python _do_handshake should do something similar, e.g., assign to self.socket.
                handshake_err = await handshake.do_handshake(self, fs, ephemeral_kp)
                if handshake_err:
                    await fs.close(0)
                    return ValueError(f"Noise handshake failed: {handshake_err}")
            except Exception as e_handshake:  # Catching exceptions if _do_handshake raises them
                await fs.close(0)
                # Return the caught exception, wrapping if necessary to match Go's error message style
                return ValueError(f"Noise handshake failed: {e_handshake}")

            # Go: go cli.keepAliveLoop(cli.socket.Context())
            # Go: go cli.handlerQueueLoop(cli.socket.Context())
            # Python: Start keepalive and handler loops
            # The Go code passes cli.socket.Context(). The Python equivalent depends on how
            # FrameSocket (or the actual NoiseSocket assigned to self.socket after handshake) exposes its context.
            if self.socket:  # self.socket should be the actual (e.g., NoiseSocket) after handshake
                socket_ctx = self.socket.context()  # Assuming a .context() method
                self._keepalive_task = asyncio.create_task(keepalive.keep_alive_loop(self))
                self._handler_task = asyncio.create_task(self._handler_queue_loop(socket_ctx))
            else:
                # This case should ideally not be reached if handshake was successful
                # and self.socket was assigned.
                logger.error("_connect: self.socket is None after successful handshake, cannot start loops.")
                return ValueError("_connect: self.socket is None after successful handshake")

            # Go: return nil
            return None

    def is_logged_in(self) -> bool:
        """Check if the client is logged in.

        Returns:
            True if the client is logged in, False otherwise
        """
        return self is not None and self._is_logged_in

    async def on_disconnect(self, ns: "NoiseSocket", remote: bool):
        """
        Handles the disconnection of a NoiseSocket.

        Args:
            ns: The NoiseSocket instance that disconnected.
            remote: True if the disconnection was initiated by the remote server,
                    False if initiated locally.
        """
        # Go: ns.Stop(false)
        # Assuming the boolean parameter to stop indicates if it's due to a remote error.
        # The Go code passes `false`, which might mean "not a remote error causing the stop call itself".
        # Let's assume `stop` is just about cleaning up the socket resources.
        await ns.stop(False)  # Or map `remote` to this boolean if it means something different for stop()

        # Go: cli.socketLock.Lock(); defer cli.socketLock.Unlock()
        async with self.socket_lock:
            # Go: if cli.socket == ns
            if self.socket == ns:
                # Go: cli.socket = nil
                self.socket = None
                # Go: cli.clearResponseWaiters(xmlStreamEndNode)
                await request.clear_response_waiters(self, request.XML_STREAM_END_NODE)

                # Go: if !cli.isExpectedDisconnect() && remote
                if not self._is_expected_disconnect() and remote:
                    # Go: cli.Log.Debugf("Emitting Disconnected event")
                    logger.debug("Emitting Disconnected event")
                    # Go: go cli.dispatchEvent(&events.Disconnected{})
                    self.create_task(self.dispatch_event(Disconnected()))
                    # Go: go cli.autoReconnect()
                    self.create_task(self.auto_reconnect())
                # Go: else if remote
                elif remote:
                    logger.debug("OnDisconnect() called, but it was expected, so not emitting event")
                # Go: else
                else:
                    logger.debug("OnDisconnect() called after manual disconnection")
            # Go: else
            else:
                logger.debug(
                    f"Ignoring OnDisconnect on different socket (current: {self.socket}, disconnected: {ns})")

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

    async def auto_reconnect(self) -> None:
        """Automatically reconnect to the server after a disconnection."""
        # Go: if !cli.EnableAutoReconnect || cli.Store.ID == nil
        if not self.enable_auto_reconnect or self.store.id is None:
            return

        # Go: for { ... }
        while True:
            # Go: autoReconnectDelay := time.Duration(cli.AutoReconnectErrors) * 2 * time.Second
            # Python: auto_reconnect_delay = self.auto_reconnect_errors * 2 (seconds)
            auto_reconnect_delay_seconds = self.auto_reconnect_errors * 2
            # Go: cli.Log.Debugf("Automatically reconnecting after %v", autoReconnectDelay)
            logger.debug(f"Automatically reconnecting after {auto_reconnect_delay_seconds} seconds")
            # Go: cli.AutoReconnectErrors++
            self.auto_reconnect_errors += 1
            # Go: time.Sleep(autoReconnectDelay)
            await asyncio.sleep(auto_reconnect_delay_seconds)

            # Go: err := cli.connect()
            # Python: try...except for _connect()
            # The Python `_connect` method in the input raises exceptions.
            # The Go `connect` method returns an error.
            # To match Go, `self._connect` should return Optional[Exception].
            err = await self._connect()

            # Go: if errors.Is(err, ErrAlreadyConnected)
            if isinstance(err, ErrAlreadyConnected):  # Check for specific error type
                logger.debug("Connect() said we're already connected after autoreconnect sleep")
                return
            # Go: else if err != nil
            elif err is not None:
                logger.error(f"Error reconnecting after autoreconnect sleep: {err}")
                # Go: if cli.AutoReconnectHook != nil && !cli.AutoReconnectHook(err)
                if self.auto_reconnect_hook is not None and not self.auto_reconnect_hook(err):
                    logger.debug("AutoReconnectHook returned false, not reconnecting")
                    return
            # Go: else (meaning err == nil, successful connection)
            else:
                # Successful connection
                logger.debug("Successfully reconnected after autoreconnect sleep.")
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
        # Go: if cli == nil || cli.socket == nil { return }
        # Python: if self is None or self.socket is None: return
        # The `self is None` check is unidiomatic for Python instance methods.
        # The check for `self.socket is None` is correct.
        if self.socket is None:
            return

        # Go: cli.socketLock.Lock()
        # Go: cli.unlockedDisconnect()
        # Go: cli.socketLock.Unlock()
        async with self.socket_lock:
            await self._unlocked_disconnect()

        # Go: cli.clearDelayedMessageRequests()
        retry.clear_delayed_message_requests(self)

    async def _unlocked_disconnect(self) -> None:
        """
        Disconnect from the WhatsApp web websocket without locking.
        This version also cancels background keepalive and handler tasks.
        """
        # --- Start of Python-specific task cancellation ---
        # This logic is not present in the Go original `unlockedDisconnect`
        # but is a common pattern for cleanup in async Python.
        if self._keepalive_task and not self._keepalive_task.done():
            logger.debug("Cancelling keepalive task")  # Use logger
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task  # Allow task to process cancellation
            except asyncio.CancelledError:
                logger.debug("Keepalive task was cancelled")
            except Exception as e:
                logger.error(f"Exception during keepalive task cancellation: {e}")
            finally:
                self._keepalive_task = None

        if self._handler_task and not self._handler_task.done():
            logger.debug("Cancelling handler task")  # Use logger
            self._handler_task.cancel()
            try:
                await self._handler_task  # Allow task to process cancellation
            except asyncio.CancelledError:
                logger.debug("Handler task was cancelled")
            except Exception as e:
                logger.error(f"Exception during handler task cancellation: {e}")
            finally:
                self._handler_task = None
        # --- End of Python-specific task cancellation ---

        # Go: if cli.socket != nil { ... }
        if self.socket is not None:
            # Go: cli.socket.Stop(true)
            # The `true` argument in Go's Stop(true) likely indicates a remote error or forceful stop.
            # Ensure the Python self.socket.stop() method handles this boolean appropriately.
            await self.socket.stop(True)
            # Go: cli.socket = nil
            self.socket = None
            # Go: cli.clearResponseWaiters(xmlStreamEndNode)
            # Python: await self._clear_response_waiters("xmlstreamend")
            # Ensure the argument matches the Go `xmlStreamEndNode`
            await request.clear_response_waiters(self, request.XML_STREAM_END_NODE)

        await self.close()

    async def close(self):
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

    async def logout(self) -> Optional[Exception]:
        """Log out from WhatsApp and delete the local device store.

        If the logout request fails, the disconnection and local data deletion will not happen either.

        Note that this will not emit any events. The LoggedOut event is only used for external logouts
        (triggered by the user from the main device or by WhatsApp servers).

        Returns:
            Optional[Exception]: None on success, or an Exception if an error occurred.
        """
        # Go: if cli == nil { return ErrClientIsNil }
        # This check is unidiomatic for Python instance methods.
        # If the client object itself is None, a TypeError would occur before this.

        # Go: else if cli.MessengerConfig != nil { return errors.New("can't logout with Messenger credentials") }
        if self.messenger_config is not None:
            return ValueError("Can't logout with Messenger credentials")

        # Go: ownID := cli.getOwnID()
        own_id = self.get_own_id()
        # Go: if ownID.IsEmpty() { return ErrNotLoggedIn }
        if own_id.is_empty():
            return ErrNotLoggedIn("Not logged in")  # Return specific error type

        # Go: _, err := cli.sendIQ(...)
        # Constructing the IQ request
        # TODO: Ensure waBinary.Node and waBinary.Attrs are correctly translated to Python equivalents
        iq_content_node = Node(
            tag="remove-companion-device",
            attrs={
                "jid": str(own_id),  # Ensure own_id is stringified if Attrs expects strings
                "reason": "user_initiated",
            }
        )
        logout_iq = InfoQuery(
            namespace="md",
            type=InfoQueryType.SET,
            to=JID.server_jid(),  # Use the defined ServerJID equivalent
            content=[iq_content_node]
        )

        _, err_iq = await self.send_iq(logout_iq)

        # Go: if err != nil { return fmt.Errorf("error sending logout request: %w", err) }
        if err_iq is not None:
            # Wrap the error to match Go's fmt.Errorf style
            return ValueError(f"error sending logout request: {err_iq}")

        # Go: cli.Disconnect()
        await self.disconnect()

        # Go: err = cli.Store.Delete(ctx)
        # The Go version passes a context.Context to Store.Delete.
        # The Python version needs to handle this. If the Python Store.delete
        # doesn't use a context, this argument can be omitted.
        # If it does, a Python equivalent of context (e.g., from asyncio or a custom one)
        # would need to be passed. For now, assuming it doesn't require one or handles None.
        # TODO: Determine how context is handled for self.store.delete()
        try:
            # Assuming self.store.delete() might raise an exception on failure
            # or return an error object if designed that way.
            # For this example, let's assume it raises an exception.
            await self.store.delete()  # Pass context if needed: await self.store.delete(ctx_equivalent)
        except Exception as err_delete:
            # Go: if err != nil { return fmt.Errorf("error deleting data from store: %w", err) }
            return ValueError(f"error deleting data from store: {err_delete}")

        # Go: return nil
        return None

    async def add_event_handler(self, handler: EventHandler) -> int:
        """Register a new async function to receive all events emitted by this client.

        Args:
            handler: The async event handler function.

        Returns:
            The event handler ID, which can be passed to remove_event_handler to remove it.
        """
        # Go: nextID := atomic.AddUint32(&nextHandlerID, 1)
        # Go uses a global atomic counter for unique IDs across all clients.
        # Python uses a per-client counter (self.id_counter) protected by a lock.
        # This is a difference in the scope of ID uniqueness (global vs per-client).
        # Using a lock around a simple integer counter is a common Python equivalent for thread/async safety.

        # Go: cli.eventHandlersLock.Lock()
        # Go: defer cli.eventHandlersLock.Unlock()
        async with self.event_handlers_lock:  # Use async with for asyncio Lock

            # Increment the counter *before* using it, matching Go's atomic.AddUint32 behavior
            self.id_counter += 1
            handler_id = self.id_counter  # Use the new value as the ID

            # Go: cli.eventHandlers = append(cli.eventHandlers, wrappedEventHandler{handler, nextID})
            # Python: self.event_handlers.append(WrappedEventHandler(handler, handler_id))
            self.event_handlers.append(WrappedEventHandler(handler, handler_id))

        # Go: return nextID
        return handler_id

    async def remove_event_handler(self, handler_id: int) -> bool:
        """Remove a previously registered event handler function.

        N.B. Do not run this directly from an event handler. That would cause a deadlock.
        Instead run it in a separate task (e.g., using asyncio.create_task).

        Args:
            handler_id: The ID of the handler to remove.

        Returns:
            True if the handler was found and removed, False otherwise.
        """
        # Go: cli.eventHandlersLock.Lock(); defer cli.eventHandlersLock.Unlock()
        async with self.event_handlers_lock:  # Use async with for asyncio.Lock
            # Go: for index := range cli.eventHandlers
            for i, wrapped_handler in enumerate(self.event_handlers):
                # Go: if cli.eventHandlers[index].id == id
                if wrapped_handler.id == handler_id:
                    # To mirror Go's behavior of nil-ing out the function reference
                    # before removing the element from the list, which can help with GC.
                    wrapped_handler.fn = None

                    # Pythonic way to remove an element by index
                    self.event_handlers.pop(i)
                    return True
        return False

    async def remove_event_handlers(self) -> None:
        """Remove all event handlers that have been registered with add_event_handler."""
        # Go: cli.eventHandlersLock.Lock()
        # Go: defer cli.eventHandlersLock.Unlock()
        async with self.event_handlers_lock:  # Use async with for asyncio.Lock
            # Go: cli.eventHandlers = make([]wrappedEventHandler, 0, 1)
            # Python: self.event_handlers = []
            # Re-assigning to a new empty list is the Python equivalent of Go's make([]type, 0, capacity)
            # for the purpose of clearing the list.
            self.event_handlers = []

    async def handle_frame(self, data: bytes):
        """
        Processes an incoming WebSocket frame.

        Args:
            data: The raw byte data of the frame.
        """
        # Go: decompressed, err := waBinary.Unpack(data)
        # Python: Assuming wa_binary.unpack returns (Optional[bytes], Optional[Exception])
        decompressed, err_unpack = unpack(data)
        if err_unpack is not None:
            logger.warning(f"Failed to decompress frame: {err_unpack}")
            logger.debug(f"Errored frame hex: {data.hex()}")
            return
        decompressed: bytes
        # Go: node, err := waBinary.Unmarshal(decompressed)
        # Python: Assuming wa_binary.unmarshal returns (Optional[Node], Optional[Exception])
        node, err_unmarshal = unmarshal(decompressed)
        if err_unmarshal is not None:
            logger.warning(f"Failed to decode node in frame: {err_unmarshal}")
            logger.debug(f"Errored frame hex: {decompressed.hex()}")
            return

        # Go: cli.recvLog.Debugf("%s", node.XMLString())
        self.recv_log.debug(f"{node.xml_string()}")

        # Go: if node.Tag == "xmlstreamend"
        if node.tag == "xmlstreamend":
            if not self._is_expected_disconnect():
                logger.warning("Received stream end frame")
            # Go: // TODO should we do something else?
            # Python: Consider if any specific cleanup or state change is needed here.
        # Go: else if cli.receiveResponse(node)
        elif await request.receive_response(self, node):
            # handled by receive_response
            pass
        # Go: else if _, ok := cli.nodeHandlers[node.Tag]; ok
        elif node.tag in self.node_handlers:
            # Go: select { case cli.handlerQueue <- node: default: ... }
            try:
                self.handler_queue.put_nowait(node)
            except asyncio.QueueFull:
                logger.warning("Handler queue is full, message ordering is no longer guaranteed. Scheduling put.")
                # Go: go func() { cli.handlerQueue <- node }()
                await self.handler_queue.put(node)

        # Go: else if node.Tag != "ack"
        elif node.tag != "ack":
            logger.debug(f"Didn't handle WhatsApp node {node.tag}")

    async def _handler_queue_loop(self, stop_event: Optional[asyncio.Event] = None) -> None:
        """
        Process nodes from the handler queue.
        Accepts an optional asyncio.Event to signal shutdown.
        """
        logger.debug("Starting handler queue loop")
        # Go: timer := time.NewTimer(5 * time.Minute); stopAndDrainTimer(timer)
        # Python: The timeout logic is handled per node processing task.

        while True:
            try:
                node = await self.handler_queue.get()

                # Go: doneChan := make(chan struct{}, 1)
                done_event = asyncio.Event()

                # Go: go func() { start := time.Now(); cli.nodeHandlers[node.Tag](node); ... }()
                async def process_node():
                    start = time.time()
                    await self.node_handlers[node.tag](node)
                    duration = time.time() - start
                    done_event.set()
                    if duration > 5.0:  # 5 seconds
                        logger.warning(f"Node handling took {duration:.2f}s for {node.xml_string()}")

                # Start the node processing task
                process_node_task = asyncio.create_task(process_node())

                # Go: timer.Reset(5 * time.Minute); select { case <-doneChan: ... case <-timer.C: ... }
                done, pending = await asyncio.wait(
                    [process_node_task],
                    timeout=300.0,  # 5 minutes
                    return_when=asyncio.FIRST_COMPLETED
                )

                if process_node_task in done:
                    # Go: case <-doneChan: stopAndDrainTimer(timer)
                    # Task completed within timeout
                    pass
                else:
                    # Go: case <-timer.C:
                    logger.warning(
                        f"Node handling is taking long for {node.xml_string()} - continuing in background")
                    # The processing task continues in background (like Go goroutine)


            except asyncio.CancelledError:
                # Go: case <-ctx.Done():
                logger.debug("Closing handler queue loop")
                return
            except Exception as e:
                logger.error(f"Error in handler queue loop: {e}")
                # Continue the loop on other errors

    async def send_node_and_get_data(self, node: Node) -> Tuple[Optional[bytes], Optional[Exception]]:
        """
        Send a node to the server and get the raw data.
        Mirrors Go's pattern of returning (data, error).

        Args:
            node: The node to send.

        Returns:
            A tuple containing the raw data sent (bytes) and an optional Exception.
        """
        # Go: if cli == nil { return nil, ErrClientIsNil }
        # This check is unidiomatic for Python instance methods.
        # If the client object itself is None, a TypeError would occur before this.
        # We can keep it if strict adherence to Go's explicit nil check is desired for the error type.
        # For now, let's assume the caller ensures `self` is not None.

        # Go: cli.socketLock.RLock(); sock := cli.socket; cli.socketLock.RUnlock()
        # Python: Acquire lock to safely access self.socket.
        # asyncio.Lock is exclusive. If RLock semantics are critical, a different lock type
        # or pattern would be needed (e.g., from `asyncio_rlock` library or custom).
        # For just getting the reference, this is okay.
        async with self.socket_lock:

            # Go: if sock == nil { return nil, ErrNotConnected }
            if self.socket is None:
                return None, ErrNotConnected("Not connected")

            # Go: payload, err := waBinary.Marshal(node)
            # Python: try...except for node.marshal()
            # To match Go's return pattern, node.marshal() should also return (data, error)
            payload, err_marshal = marshal(node)  # Assuming node.marshal() returns (bytes, error)
            payload: bytes
            if err_marshal is not None:
                # Go: return nil, fmt.Errorf("failed to marshal node: %w", err)
                return None, ValueError(f"Failed to marshal node: {err_marshal}")

            if payload is None:  # Should not happen if err_marshal is None, but good practice
                return None, ValueError("Marshaling returned no data and no error")

            # Go: cli.sendLog.Debugf("%s", node.XMLString())
            self.send_log.debug(f"{node.xml_string()}")

            # Go: return payload, sock.SendFrame(payload)
            # Python: await sock.send_frame(payload)
            # To match Go, sock.send_frame should return an error or None
            err_send = await self.socket.send_frame(payload)
            if err_send is not None:
                return payload, err_send  # Return payload even on send error, as Go does

            return payload, None

    async def send_node(self, node: Node) -> Optional[Exception]:
        """Send a node to the server.

        Args:
            node: The node to send.

        Returns:
            Optional[Exception]: An exception object if an error occurred, otherwise None.
        """
        # Go: _, err := cli.sendNodeAndGetData(node)
        # Python: Assuming self.send_node_and_get_data returns (data, error_object)
        _payload, err = await self.send_node_and_get_data(node)

        # Go: return err
        return err

    async def dispatch_event(self, evt: events.BaseEvent) -> None:
        """Dispatch an event to all registered event handlers.

        Args:
            evt: The event to dispatch
        """
        # Go: cli.eventHandlersLock.RLock()
        # Python: Acquire lock to safely iterate over self.event_handlers.
        # asyncio.Lock is exclusive. If RLock semantics are critical and handlers
        # can be added/removed *during* dispatch by another task (which is generally
        # a bad idea and can lead to issues even with RLock if not careful),
        # a more complex lock or a copy of the list might be needed.
        # For now, assuming exclusive lock is acceptable for iteration.
        async with self.event_handlers_lock:
            # Create a copy of the handlers list before iterating.
            # This prevents issues if a handler tries to modify the list
            # (e.g., remove itself) during iteration, which would be problematic
            # even with a read lock in Go if not handled carefully.
            # The Go version's RLock prevents modification of the slice header,
            # but not concurrent modification of the underlying array if a handler
            # somehow got a reference to it and modified it (highly unlikely for Add/Remove).
            # A copy is safer in Python for this pattern.
            handlers_to_dispatch = list(self.event_handlers)

        # Go: defer func() { ... recover() ... }()
        # Python: The try/except block outside the loop aims to mimic the
        # single recover() for the entire dispatch operation. However, Python's
        # exceptions don't quite work like Go's panics + recover in a defer.
        # A panic in one Go handler would be caught by the single defer.
        # In Python, an unhandled exception in one `await handler.fn(evt)`
        # would stop the loop unless caught individually.
        # The provided Python code catches exceptions per handler, which is often
        # a more robust approach in Python event systems (one bad handler doesn't
        # stop others). We'll keep that per-handler try-except.
        # If a single catch for the whole loop is desired, it would be more complex
        # to also get the Go behavior of continuing to other handlers after a panic.

        for handler_wrapper in handlers_to_dispatch:
            if handler_wrapper.fn is None:  # Handler might have been removed (fn set to None)
                continue
            try:
                # Go: handler.fn(evt)
                # Python: await handler.fn(evt)
                await handler_wrapper.fn(evt)
            except Exception as err:
                # Go: cli.Log.Errorf("Event handler panicked while handling a %T: %v\n%s", evt, err, debug.Stack())
                # Python: logger.exception(...)
                logger.exception(f"Event handler panicked while handling a {type(evt).__name__}")

    # The method can be synchronous if all its internal calls are synchronous.
    # If get_own_id or JID.parse were async, this would need to be async.
    # For direct porting of Go's synchronous logic, this can be synchronous.
    def parse_web_message(self, chat_jid: JID, web_msg: waWeb_pb2.WebMessageInfo) -> Tuple[
        Optional[events.Message], Optional[Exception]]:
        """
        Parse a WebMessageInfo object into an events.Message.
        Mirrors Go's pattern of returning (value, error).

        Args:
            chat_jid: The JID of the chat.
            web_msg: The WebMessageInfo protobuf object to parse.

        Returns:
            A tuple containing an events.Message object or None, and an Exception or None.
        """
        err: Optional[Exception] = None

        # Go: if chatJID.IsEmpty()
        if chat_jid.is_empty():
            # Go: chatJID, err = types.ParseJID(webMsg.GetKey().GetRemoteJID())
            parsed_jid, err_parse = JID.parse_jid(web_msg.GetKey().remote_jid)
            if err_parse:
                return None, ValueError(f"no chat JID provided and failed to parse remote JID: {err_parse}")
            if parsed_jid is None:  # Should not happen if err_parse is None
                return None, ValueError("no chat JID provided and remote JID parsing yielded None without error")
            chat_jid = parsed_jid

        # Go: info := types.MessageInfo{...}
        message_source = MessageSource(
            chat=chat_jid,
            is_from_me=web_msg.GetKey().from_me,
            is_group=(chat_jid.server == GROUP_SERVER)  # Assuming GROUP_SERVER constant
        )
        info = MessageInfo(
            message_source=message_source,
            id=web_msg.GetKey().id,
            push_name=web_msg.GetPushName(),
            # Go: time.Unix(int64(webMsg.GetMessageTimestamp()), 0)
            timestamp=datetime.datetime.fromtimestamp(web_msg.GetMessageTimestamp(), tz=datetime.timezone.utc)
        )

        # Determine sender
        # Go: if info.IsFromMe
        if info.message_source.is_from_me:
            own_id_non_ad = self.get_own_id().to_non_ad()
            if own_id_non_ad.is_empty():
                return None, ErrNotLoggedIn("Not logged in (own ID is empty after to_non_ad)")
            info.message_source.sender = own_id_non_ad
        # Go: else if chatJID.Server == types.DefaultUserServer ...
        elif chat_jid.server in [DEFAULT_USER_SERVER, HIDDEN_USER_SERVER, NEWSLETTER_SERVER]:
            info.message_source.sender = chat_jid
        # Go: else if webMsg.GetParticipant() != ""
        elif web_msg.GetParticipant():
            info.message_source.sender, err = JID.parse_jid(web_msg.GetParticipant())
        # Go: else if webMsg.GetKey().GetParticipant() != ""
        elif web_msg.GetKey().participant:  # Assuming GetKey() returns object with .participant
            info.message_source.sender, err = JID.parse_jid(web_msg.GetKey().participant)
        else:
            return None, ValueError(f"couldn't find sender of message {info.id}")

        if err:
            return None, ValueError(f"failed to parse sender of message {info.id}: {err}")
        if info.sender is None and not info.message_source.is_from_me:  # Double check if sender was set
            return None, ValueError(f"sender could not be determined for message {info.id}")

        # Go: if pk := webMsg.GetCommentMetadata().GetCommentParentKey(); pk != nil
        comment_meta = web_msg.GetCommentMetadata()
        if comment_meta:
            pk = comment_meta.GetCommentParentKey()
            if pk:
                info.msg_meta_info.thread_message_id = pk.GetID()
                # Go: info.MsgMetaInfo.ThreadMessageSenderJID, _ = types.ParseJID(pk.GetParticipant())
                # Error from this specific JID parse is ignored in Go
                parsed_thread_sender_jid, _ = JID.parse_jid(pk.GetParticipant())
                info.msg_meta_info.thread_message_sender_jid = parsed_thread_sender_jid

        # Go: evt := &events.Message{...}
        evt = events.Message(
            raw_message=web_msg.GetMessage(),
            source_web_msg=web_msg,
            info=info
        )

        # Go: evt.UnwrapRaw()
        evt.unwrap_raw()  # Assuming this method exists and modifies evt.message

        # Go: if evt.Message.GetProtocolMessage().GetType() == waE2E.ProtocolMessage_MESSAGE_EDIT
        # Ensure evt.message and protocol_message are not None before accessing
        if evt.message and evt.message.GetProtocolMessage():
            protocol_msg = evt.message.GetProtocolMessage()
            if protocol_msg.GetType() == waE2E_pb2.ProtocolMessage.MESSAGE_EDIT:
                if protocol_msg.GetKey():
                    info.id = protocol_msg.GetKey().id  # Update MessageInfo's ID
                evt.message = protocol_msg.GetEditedMessage()  # Update the actual message content

        return evt, None

    async def store_lid_pn_mapping(self, first: JID, second: JID) -> None:
        """Store a mapping between a LID (Local ID) and a PN (Phone Number JID).

        Args:
            first: The first JID.
            second: The second JID.
            ctx: Optional context, similar to Go's context.Context (usage depends on store implementation).
        """
        lid: Optional[JID] = None
        pn: Optional[JID] = None

        # Go: if first.Server == types.HiddenUserServer && second.Server == types.DefaultUserServer
        # Python: Use defined constants for server types
        if first.server == HIDDEN_USER_SERVER and second.server == DEFAULT_USER_SERVER:
            lid = first
            pn = second
        # Go: else if first.Server == types.DefaultUserServer && second.Server == types.HiddenUserServer
        elif first.server == DEFAULT_USER_SERVER and second.server == HIDDEN_USER_SERVER:
            lid = second
            pn = first
        else:
            # If conditions are not met, the function should simply return, as in Go.
            return

        # Ensure lid and pn were assigned (should always be if we didn't return early)
        if lid is None or pn is None:
            # This case should ideally not be reached if the logic above is correct
            logger.error("LID or PN was not assigned despite passing initial checks in store_lid_pn_mapping.")
            return

        # Go: err := cli.Store.LIDs.PutLIDMapping(ctx, lid, pn)
        # Python: Call the store method, passing the context if the Python store uses it.
        # The Python store method might raise an exception or return an error object.
        # Assuming it returns Optional[Exception] to match Go's error handling better.
        err: Optional[Exception]
        try:
            # Pass ctx if your Python store's put_lid_mapping expects it.
            # If it doesn't, you can omit it: await self.store.lids.put_lid_mapping(lid, pn)
            err = await self.store.lids.put_lid_mapping(lid, pn)
        except Exception as e:  # Catch if put_lid_mapping raises directly
            err = e

        # Go: if err != nil { cli.Log.Errorf("Failed to store LID-PN mapping for %s -> %s: %v", lid, pn, err) }
        if err is not None:
            # Use logger for consistency
            logger.error(f"Failed to store LID-PN mapping for {lid} -> {pn}: {err}")
