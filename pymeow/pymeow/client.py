"""
WhatsApp Web client implementation.

Port of whatsmeow/client.go
"""
import asyncio
import datetime
import logging
import socket
import time
from dataclasses import dataclass, field
from os import urandom
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import aiohttp

from . import connectionevents, handshake, keepalive, request, retry
from .appstate.keys import Processor
from .binary.decoder import DecodingError
from .binary.node import Node, marshal, unmarshal
from .binary.unpack import unpack
from .call import handle_call_event
from .connectionevents import handle_ib
from .exceptions import ErrAlreadyConnected, ErrNotConnected, ErrNotLoggedIn
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from .generated.waE2E.WAWebProtobufsE2E_pb2 import Message
from .generated.waWeb import WAWebProtobufsWeb_pb2 as waWeb_pb2
from .mediaconn import MediaConn
from .message import handle_encrypted_message
from .notification import handle_notification
from .pair import handle_iq
from .pair_code import PhoneLinkingCache
from .presence import handle_chat_state, handle_presence
from .privacysettings import PrivacySettings
from .receipt import handle_receipt
from .retry import RecentMessage, RecentMessageKey
from .socket.framesocket import FrameSocket
from .socket.noisesocket import NoiseSocket
from .store.store import Device
from .store.tortoise_signal_store_implementation import (
    SignalPreKeyModel,
    TortoiseSignalStore,
    generate_identity_keys,
    generate_prekeys,
)
from .datatypes.events import Disconnected, events
from .datatypes.jid import DEFAULT_USER_SERVER, EMPTY_JID, GROUP_SERVER, HIDDEN_USER_SERVER, JID, NEWSLETTER_SERVER
from .datatypes.message import AddressingMode, MessageID, MessageInfo, MessageSource
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
        self.store: Device = device_store
        self.recv_log = logging.getLogger(f"{logger.name}.Recv")
        self.send_log = logging.getLogger(f"{logger.name}.Send")

        # Socket-related fields
        self.socket: Optional[NoiseSocket] = None
        self.socket_lock = asyncio.Lock()
        self.socket_wait = asyncio.Event()

        # State flags
        self._is_logged_in = False
        self._expected_disconnect = False
        self.enable_auto_reconnect = True
        self.initial_auto_reconnect = False
        self.last_successful_connect: Optional[datetime.datetime] = None
        self.auto_reconnect_errors = 0
        self.auto_reconnect_hook: Optional[Callable[[Exception], bool]] = None
        self.synchronous_ack = False
        self.enable_decrypted_event_buffer = False
        self.last_decrypted_buffer_clear: Optional[datetime.datetime] = None

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
        self.history_sync_notifications: asyncio.Queue[waE2E_pb2.HistorySyncNotification] = asyncio.Queue(32)
        self.history_sync_handler_started = False

        self.upload_prekeys_lock = asyncio.Lock()
        self.last_pre_key_upload: Optional[datetime.datetime] = None

        # Import JID here to avoid circular imports
        from .datatypes import JID
        self.server_jid = JID.server_jid()

        self.media_conn_cache: MediaConn
        self.media_conn_lock = asyncio.Lock()

        # Response handling
        # TODO: Type hint for response_waiters values (should be asyncio.Queue[Node])
        self.response_waiters: Dict[str, asyncio.Queue[Node]] = {}
        self.response_waiters_lock = asyncio.Lock()

        # Event handling
        self.node_handlers: Dict[str, Callable[[Client, Node], Awaitable[None]]] = {
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

        # Go: chan *waBinary.Node (unbuffered or default size) -> Python: asyncio.Queue(HANDLER_QUEUE_SIZE)
        # The buffer size (HANDLER_QUEUE_SIZE=2048) is a behavioral difference from an unbuffered Go channel.
        # Consider asyncio.Queue() for an unbounded queue or asyncio.Queue(1) for closer to unbuffered semantics if backpressure is important.
        # TODO: Type hint for handler_queue queue items
        self.handler_queue: asyncio.Queue[Any] = asyncio.Queue(HANDLER_QUEUE_SIZE)
        self.event_handlers: Set[EventHandler] = set()

        # Message handling
        self.message_retries: Dict[str, int] = {}
        self.message_retries_lock = asyncio.Lock()

        # TODO: Type hint for incoming_retry_request_counter keys
        self.incoming_retry_request_counter: Dict[Any, int] = {}
        self.incoming_retry_request_counter_lock = asyncio.Lock()

        # Go: map[string]time.Time -> Python: Dict[str, datetime] (OK)
        self.app_state_key_requests: Dict[str, float] = {}
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
        self.recent_messages_map: Dict[RecentMessageKey, RecentMessage] = {}
        # Go: [recentMessagesSize]recentMessageKey (fixed-size array) -> Python: List[recentMessageKey] (dynamic list)
        # This is a behavioral difference. If fixed size is critical, a different Python structure might be needed.
        # TODO: Type hint for recent_messages_list items
        self.recent_messages_list: List[Any] = []  # Go has a fixed-size array, Python has a dynamic list.
        self.recent_messages_ptr = 0  # Go: int -> Python: int (OK)
        self.recent_messages_lock = asyncio.Lock()

        self.session_recreate_history: Dict[JID, datetime.datetime] = {}
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

        self.phone_linking_cache: PhoneLinkingCache

        # Generate a unique ID prefix
        unique_id_prefix = urandom(2)
        self.unique_id = f"{unique_id_prefix[0]}.{unique_id_prefix[1]}-"
        self.id_counter = 0

        self.http: aiohttp.ClientSession = aiohttp.ClientSession(trust_env=True)

        # Messenger config (for non-WhatsApp clients)
        self.messenger_config: Optional[
            MessengerConfig] = None  # Go: *MessengerConfig -> Python: Optional[MessengerConfig] (OK)

        # These are extra attributes in Python, likely for managing async tasks.
        self._keepalive_task: Optional[asyncio.Task] = None
        self._handler_task: Optional[asyncio.Task] = None

        self._background_tasks: Set[asyncio.Task] = set()

        # used by the signal_protocol lib
        self.signal_store: TortoiseSignalStore
        # self.session_ciphers = {}  # Cache for session ciphers
        # self.group_ciphers = {}  # Cache for group ciphers

    async def ainit(self) -> 'Client':
        await self.initialize_signal_protocol()
        return self

    async def initialize_signal_protocol(self) -> None:
        """Initialize Signal Protocol on startup."""
        logger.debug("Initializing Signal protocol...")

        # 1. Generate or load identity keys
        identity_keys = generate_identity_keys()
        registration_id = 12345  # Should be randomly generated and stored

        # 2. Create your persistent store
        self.signal_store = TortoiseSignalStore(identity_keys, registration_id)

        # 3. Generate and store prekeys if this is first run
        await self._setup_prekeys()

        print("Signal Protocol initialized with persistent storage")

    async def _setup_prekeys(self) -> None:
        """Generate prekeys on first run."""
        # Check if we already have prekeys
        existing_prekeys = await SignalPreKeyModel.all().count()
        if existing_prekeys == 0:
            # Generate 100 prekeys
            prekeys = generate_prekeys(1, 100)
            for prekey in prekeys:
                await self.signal_store.asave_pre_key(prekey.id(), prekey)
            print(f"Generated {len(prekeys)} prekeys")

    def create_task(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
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

    async def close_socket_wait_chan(self) -> None:
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

    async def connect(self) -> None:
        """Connect to the WhatsApp web websocket.

        After connection, it will either authenticate if there's data in the device store,
        or emit a QR event to set up a new link.

        Raises:
            Exception
        """
        try:
            await self._connect()
        except (aiohttp.ClientConnectionError,
                aiohttp.ClientError,
                ConnectionError,
                OSError,
                socket.error,
                asyncio.TimeoutError,
                aiohttp.ServerTimeoutError,
                ):
            if self.initial_auto_reconnect and self.enable_auto_reconnect:
                logger.error("Initial connection failed but reconnecting in background")

                self.create_task(self.dispatch_event(Disconnected()))
                self.create_task(self.auto_reconnect())

                # Go: return nil (meaning the public Connect() call doesn't propagate this specific error)
                return None  # Explicitly return None for clarity
            else:
                raise

    async def _connect(self) -> None:
        """Internal method to establish a connection to the WhatsApp web websocket.

        Raises:
            Exception
            ErrAlreadyConnected
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
                    raise ErrAlreadyConnected()

            self._reset_expected_disconnect()

            # Go: fs := socket.NewFrameSocket(cli.Log.Sub("Socket"), wsDialer)
            # Python: Pass logger and dialer config to FrameSocket constructor
            fs = FrameSocket(dialer=self.http)  # todo: check if this is saved, socket needs to be closed?

            if self.messenger_config is not None:
                fs.url = self.messenger_config.websocket_url
                fs.http_headers["Origin"] = self.messenger_config.base_url
                fs.http_headers["User-Agent"] = self.messenger_config.user_agent
                fs.http_headers["Cache-Control"] = "no-cache"
                fs.http_headers["Pragma"] = "no-cache"

            try:
                await fs.connect()
            except Exception:
                await fs.close(0)
                raise

            # Go: else if err = cli.doHandshake(fs, *keys.NewKeyPair()); err != nil { ... }
            # Python: Perform handshake
            ephemeral_kp = KeyPair.generate()
                # In Go, cli.doHandshake assigns the resulting NoiseSocket to cli.socket.
                # The Python _do_handshake should do something similar, e.g., assign to self.socket.
            try:
                await handshake.do_handshake(self, fs, ephemeral_kp)
            except:
                await fs.close(0)
                raise

            # Go: go cli.keepAliveLoop(cli.socket.Context())
            # Go: go cli.handlerQueueLoop(cli.socket.Context())
            # Python: Start keepalive and handler loops
            # The Go code passes cli.socket.Context(). The Python equivalent depends on how
            # FrameSocket (or the actual NoiseSocket assigned to self.socket after handshake) exposes its context.
            if self.socket:  # self.socket should be the actual (e.g., NoiseSocket) after handshake
                self._keepalive_task = asyncio.create_task(keepalive.keep_alive_loop(self))
                self._handler_task = asyncio.create_task(self._handler_queue_loop())
            else:
                # This case should ideally not be reached if handshake was successful
                # and self.socket was assigned.
                logger.error("_connect: self.socket is None after successful handshake, cannot start loops.")
                raise ValueError("_connect: self.socket is None after successful handshake")

    def is_logged_in(self) -> bool:
        """Check if the client is logged in.

        Returns:
            True if the client is logged in, False otherwise
        """
        return self is not None and self._is_logged_in

    async def on_disconnect(self, ns: "NoiseSocket", remote: bool) -> None:
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
            try:
                await self._connect()
            except ErrAlreadyConnected:  # Check for specific error type
                logger.debug("Connect() said we're already connected after autoreconnect sleep")
                return
            except Exception as e:
                logger.error(f"Error reconnecting after autoreconnect sleep: {e}")
                # Go: if cli.AutoReconnectHook != nil && !cli.AutoReconnectHook(err)
                if self.auto_reconnect_hook is not None and not self.auto_reconnect_hook(e):
                    logger.debug("AutoReconnectHook returned false, not reconnecting")
                    return
            # Go: else (meaning err == nil, successful connection)
            # Successful connection
            logger.debug("Successfully reconnected after autoreconnect sleep.")

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
        await retry.clear_delayed_message_requests(self)

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

    async def close(self) -> None:
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        await self.http.close()

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

        _ = await request.send_iq(self, logout_iq)

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

    def add_event_handler(self, handler: EventHandler) -> EventHandler:
        """Register a new async function to receive all events emitted by this client.

        Args:
            handler: The async event handler function.

        Returns:
            The event handler ID, which can be passed to remove_event_handler to remove it.
        """
        self.event_handlers.add(handler)
        return handler  # Return for lambda users who want to remove later

    def remove_event_handler(self, handler: EventHandler) -> bool:
        """Remove a previously registered event handler function.

        N.B. Do not run this directly from an event handler. That would cause a deadlock.
        Instead run it in a separate task (e.g., using asyncio.create_task).

        Args:
            handler: The same async event handler function used to add but now to remove.

        Returns:
            True if the handler was found and removed, False otherwise.
        """
        try:
            self.event_handlers.remove(handler)
            return True
        except KeyError:
            return False

    async def remove_event_handlers(self) -> None:
        """Remove all event handlers that have been registered with add_event_handler."""
        self.event_handlers.clear()

    async def handle_frame(self, data: bytes) -> None:
        """
        Processes an incoming WebSocket frame.

        Args:
            data: The raw byte data of the frame.
        """
        # Go: decompressed, err := waBinary.Unpack(data)
        # Python: Assuming wa_binary.unpack returns (Optional[bytes], Optional[Exception])
        decompressed = unpack(data)

        # Go: node, err := waBinary.Unmarshal(decompressed)
        # Python: Assuming wa_binary.unmarshal returns (Optional[Node], Optional[Exception])
        try:
            node = unmarshal(decompressed)
        except DecodingError as e:
            logger.warning(f"Failed to decode node in frame: {e}")
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

    async def _handler_queue_loop(self) -> None:
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
                async def process_node() -> None:
                    start = time.time()
                    await self.node_handlers[node.tag](self, node)
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

    async def send_node_and_get_data(self, node: Node) -> bytes:
        """
        Send a node to the server and get the raw data.
        Mirrors Go's pattern of returning (data, error).

        Args:
            node: The node to send.

        Returns:
            the raw data sent (bytes)
        Raises:
            ErrNotConnected
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
                raise ErrNotConnected("Not connected")

            # Go: payload, err := waBinary.Marshal(node)
            # Python: try...except for node.marshal()
            # To match Go's return pattern, node.marshal() should also return (data, error)
            payload = marshal(node)  # Assuming node.marshal() returns (bytes, error)

            # Go: cli.sendLog.Debugf("%s", node.XMLString())
            self.send_log.debug(f"{node.xml_string()}")

            # Go: return payload, sock.SendFrame(payload)
            # Python: await sock.send_frame(payload)
            # To match Go, sock.send_frame should return an error or None
            await self.socket.send_frame(payload)
            return payload

    async def send_node(self, node: Node) -> None:
        """Send a node to the server.

        Args:
            node: The node to send.

        Returns: None
        """
        # Go: _, err := cli.sendNodeAndGetData(node)
        # Python: Assuming self.send_node_and_get_data returns (data, error_object)
        _payload = await self.send_node_and_get_data(node)

    async def dispatch_event(self, evt: events.BaseEvent) -> None:
        """Dispatch an event to all registered event handlers.

        Args:
            evt: The event to dispatch
        """
        # maybe we could use gather if we have many handlers
        for handler in list(self.event_handlers):
            try:
                await handler(evt)
            except Exception as e:
                logger.exception(f"Event handler raised while handling a {type(evt).__name__}: {e}")

    # The method can be synchronous if all its internal calls are synchronous.
    # If get_own_id or JID.parse were async, this would need to be async.
    # For direct porting of Go's synchronous logic, this can be synchronous.
    def parse_web_message(self, chat_jid: JID, web_msg: waWeb_pb2.WebMessageInfo) -> events.Message:
        """
        Parse a WebMessageInfo object into an events.Message.
        Mirrors Go's pattern of returning (value, error).

        Args:
            chat_jid: The JID of the chat.
            web_msg: The WebMessageInfo protobuf object to parse.

        Returns:
            events.Message object
        Raises:
            ErrNotLoggedIn
            ValueError
        """
        # Go: if chatJID.IsEmpty()
        if chat_jid.is_empty():
            # Go: chatJID, err = types.ParseJID(webMsg.GetKey().GetRemoteJID())
            parsed_jid = JID.parse_jid(web_msg.key.remoteJID)
            chat_jid = parsed_jid

        # Go: info := types.MessageInfo{...}
        message_source = MessageSource(
            chat=chat_jid,
            is_from_me=web_msg.key.fromMe,
            is_group=(chat_jid.server == GROUP_SERVER)
        )
        info = MessageInfo(
            message_source=message_source,
            id=MessageID(web_msg.key.ID),
            push_name=web_msg.pushName,
            # Go: time.Unix(int64(webMsg.GetMessageTimestamp()), 0)
            timestamp=datetime.datetime.fromtimestamp(web_msg.messageTimestamp, tz=datetime.timezone.utc)
        )

        # Determine sender
        # Go: if info.IsFromMe
        if info.message_source.is_from_me:
            own_id_non_ad = self.get_own_id().to_non_ad()
            if own_id_non_ad.is_empty():
                raise ErrNotLoggedIn("Not logged in (own ID is empty after to_non_ad)")
            info.message_source.sender = own_id_non_ad
        # Go: else if chatJID.Server == types.DefaultUserServer ...
        elif chat_jid.server in [DEFAULT_USER_SERVER, HIDDEN_USER_SERVER, NEWSLETTER_SERVER]:
            info.message_source.sender = chat_jid
        # Go: else if webMsg.GetParticipant() != ""
        elif web_msg.participant:
            info.message_source.sender = JID.parse_jid(web_msg.participant)
        # Go: else if webMsg.GetKey().GetParticipant() != ""
        elif web_msg.key.participant:
            info.message_source.sender = JID.parse_jid(web_msg.key.participant)
        else:
            raise ValueError(f"couldn't find sender of message {info.id}")

        if info.sender is None and not info.message_source.is_from_me:
            raise ValueError(f"sender could not be determined for message {info.id}")

        # Go: if pk := webMsg.GetCommentMetadata().GetCommentParentKey(); pk != nil
        if web_msg.commentMetadata and web_msg.commentMetadata.commentParentKey:
            pk = web_msg.commentMetadata.commentParentKey
            info.msg_meta_info.thread_message_id = MessageID(pk.ID)
            # Go: info.MsgMetaInfo.ThreadMessageSenderJID, _ = types.ParseJID(pk.GetParticipant())
            parsed_thread_sender_jid = JID.parse_jid(pk.participant)
            info.msg_meta_info.thread_message_sender_jid = parsed_thread_sender_jid

        # Go: evt := &events.Message{...}
        evt = events.Message(
            raw_message=web_msg.message,
            source_web_msg=web_msg,
            info=info
        )

        # Go: evt.UnwrapRaw()
        evt.unwrap_raw()

        # Go: if evt.Message.GetProtocolMessage().GetType() == waE2E.ProtocolMessage_MESSAGE_EDIT
        if evt.message and evt.message.protocolMessage:
            protocol_msg = evt.message.protocolMessage
            if protocol_msg.type == waE2E_pb2.ProtocolMessage.MESSAGE_EDIT:
                if protocol_msg.key:
                    info.id = protocol_msg.key.ID
                evt.message = protocol_msg.editedMessage

        return evt

    async def store_lid_pn_mapping(self, first: JID, second: JID) -> None:
        """Store a mapping between a LID (Local ID) and a PN (Phone Number JID).

        Args:
            first: The first JID.
            second: The second JID.
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
        try:
            # Pass ctx if your Python store's put_lid_mapping expects it.
            # If it doesn't, you can omit it: await self.store.lids.put_lid_mapping(lid, pn)
            await self.store.lids.put_lid_mapping(lid, pn)
        except Exception as e:  # Catch if put_lid_mapping raises directly
            logger.exception(f"Failed to store LID-PN mapping for {lid} -> {pn}: {e}")

    async def my_get_message_for_retry(self, sender: JID, chat: JID, message_id: MessageID) -> Optional[Message]:
        # todo: message storage systems (databases, files, etc.) to provide messages for retry scenarios.
        return None
        # my_message_retrieval(sender, chat, message_id):
        # User's custom logic
        # return retrieve_from_my_database(sender, chat, message_id)

