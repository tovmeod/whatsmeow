"""
Events module for PyMeow - defines all event types that can be emitted by the client.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union, Set, Type, TypeVar, Generic, Tuple, Literal

from ..types import (
    JID,
    Message,
    MessageInfo,
    MessageKey,
    MessageStatus,
    MessageType,
    Presence as PresenceType,
    ChatPresence as ChatPresenceType,
    ChatPresenceMedia as ChatPresenceMediaType,
    PrivacySettings
)

T = TypeVar('T')

class Event:
    """Base class for all PyMeow events."""
    pass

class PermanentDisconnect(Event):
    """Base class for permanent disconnection events."""
    def description(self) -> str:
        """Return a human-readable description of the disconnection reason."""
        raise NotImplementedError

@dataclass
class QR(Event):
    """Emitted when QR codes are available for authentication.

    The QR codes are available in the codes list. You should render the strings as QR codes one by one,
    switching to the next one whenever enough time has passed. WhatsApp web shows the first code for 60
    seconds and all other codes for 20 seconds.

    When the QR code has been scanned and pairing is complete, PairSuccess will be emitted.
    """
    codes: List[str]

@dataclass
class PairSuccess(Event):
    """Emitted after the QR code has been scanned and the handshake has been completed.

    Note that this is generally followed by a websocket reconnection, so you should
    wait for the Connected event before trying to send anything.
    """
    id: JID
    lid: JID
    business_name: str
    platform: str

@dataclass
class PairError(Event):
    """Emitted when a pair-success event is received but finishing the pairing locally fails."""
    id: JID
    lid: JID
    business_name: str
    platform: str
    error: Exception

@dataclass
class QRScannedWithoutMultidevice(Event):
    """Emitted when the pairing QR code is scanned, but the phone doesn't have multidevice enabled.

    The same QR code can still be scanned after this event, which means the user can just be told
    to enable multidevice and re-scan the code.
    """
    pass

class Connected(Event):
    """Emitted when the client has successfully connected to the WhatsApp servers and is authenticated."""
    pass

@dataclass
class KeepAliveTimeout(Event):
    """Emitted when the keepalive ping request to WhatsApp web servers times out.

    Note: There's no automatic handling for these, but the TCP connection will eventually
    either start working again or notice it's dead on its own.
    """
    error_count: int
    last_success: datetime

class KeepAliveRestored(Event):
    """Emitted if the keepalive pings start working again after some KeepAliveTimeout events."""
    pass

@dataclass
class LoggedOut(PermanentDisconnect):
    """Emitted when the client has been unpaired from the phone.

    This can happen while connected or right after connecting.
    This will not be emitted when the logout is initiated by this client.
    """
    on_connect: bool
    reason: 'ConnectFailureReason'

    def description(self) -> str:
        return f"Logged out: {self.reason}"

class StreamReplaced(PermanentDisconnect):
    """Emitted when the client is disconnected by another client with the same session.

    This can happen if you accidentally start another process with the same session
    or otherwise try to connect twice with the same session.
    """
    def description(self) -> str:
        return "Disconnected: Another client connected with the same session"

class ManualLoginReconnect(Event):
    """Emitted after login if DisableLoginAutoReconnect is set."""
    pass

class ClientOutdated(PermanentDisconnect):
    """Emitted when the client version is too old to connect to the server."""
    def description(self) -> str:
        return "Client version is too old, please update"

class CATRefreshError(PermanentDisconnect):
    """Emitted when the client fails to refresh the CAT (Client Authentication Token)."""
    error: Exception

    def description(self) -> str:
        return f"Failed to refresh authentication token: {self.error}"

class TempBanReason(Enum):
    """Reason codes for temporary bans."""
    SENT_TOO_MANY_PEOPLE = 101
    BLOCKED_BY_USERS = 102
    CREATED_TOO_MANY_GROUPS = 103
    SENT_TOO_MANY_SAME_MESSAGE = 104
    BROADCAST_LIST_REPORT = 105
    CODE_VERIFICATION = 110
    FLOODING = 111
    BLOCK_CONTACT = 112
    SPAM_GROUP_ADD = 113
    GROUP_INVITE_JOIN = 114
    GROUP_ADD = 115
    BROADCAST_LIST_MESSAGE = 116
    PROFILE_PHOTO = 117

    def __str__(self) -> str:
        return f"{self.name.lower().replace('_', ' ')} ({self.value})"

@dataclass
class TemporaryBan(PermanentDisconnect):
    """Emitted when the account is temporarily banned."""
    code: TempBanReason
    expire: int  # Seconds until ban expires

    def description(self) -> str:
        return f"Temporarily banned: {self.code} (expires in {self.expire} seconds)"

class ConnectFailureReason(Enum):
    """Reason codes for connection failures."""
    GENERIC = 400
    LOGGED_OUT = 401
    TEMP_BANNED = 402
    BLOCKED = 403
    VERSION_TOO_OLD = 405
    OVERLOADED = 500
    EXPIRED_TOKEN = 401
    CLIENT_OUTDATED = 405
    BAD_USER_AGENT = 409
    INTERNAL_SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503
    UNKNOWN = 0

    def is_logged_out(self) -> bool:
        """Return True if this failure indicates the session is logged out."""
        return self in (self.LOGGED_OUT, self.EXPIRED_TOKEN)

    def __str__(self) -> str:
        return f"{self.name.lower().replace('_', ' ')} ({self.value})"

@dataclass
class ConnectFailure(PermanentDisconnect):
    """Emitted when there's a connection failure with a specific reason code."""
    reason: ConnectFailureReason
    message: str
    raw: Any = None

    def description(self) -> str:
        return f"Connection failed: {self.reason} - {self.message}"

@dataclass
class StreamError(Event):
    """Emitted when the server sends a stream error."""
    code: str
    raw: Any = None

class Disconnected(Event):
    """Emitted when the websocket connection is closed by the server."""
    pass

class HistorySync(Event):
    """Emitted when receiving a history sync from the server.

    This contains a batch of messages and other data that the server sends
    when the client first connects or after being offline.
    """
    def __init__(self, data: Dict[str, Any]):
        self.data = data

class DecryptFailMode(Enum):
    """Modes for handling undecryptable messages."""
    SHOW = ""
    HIDE = "hide"
    PENDING = "pending"

class UnavailableType(Enum):
    """Types of unavailable messages."""
    UNKNOWN = ""
    VIEW_ONCE = "view_once"

@dataclass
class UndecryptableMessage(Event):
    """Emitted when receiving a new message that failed to decrypt.

    The library will automatically ask the sender to retry. If the sender resends the message
    and it's decryptable, then it will be emitted as a normal Message event.
    """
    info: MessageInfo
    is_unavailable: bool = False
    unavailable_type: UnavailableType = UnavailableType.UNKNOWN
    decrypt_fail_mode: DecryptFailMode = DecryptFailMode.SHOW

@dataclass
class NewsletterMessageMeta:
    """Metadata for newsletter messages."""
    edit_ts: datetime
    original_ts: datetime

@dataclass
class Message(Event):
    """Emitted when receiving a new message."""
    info: MessageInfo
    message: Dict[str, Any]
    is_ephemeral: bool = False
    is_view_once: bool = False
    is_view_once_v2: bool = False
    is_view_once_v2_extension: bool = False
    is_document_with_caption: bool = False
    is_lottie_sticker: bool = False
    is_edit: bool = False
    source_web_msg: Optional[Dict[str, Any]] = None
    unavailable_request_id: Optional[str] = None
    retry_count: int = 0
    newsletter_meta: Optional[NewsletterMessageMeta] = None
    raw_message: Optional[Dict[str, Any]] = None

@dataclass
class FBMessage(Event):
    """Emitted when receiving a Facebook message."""
    info: MessageInfo
    message: Dict[str, Any]
    retry_count: int = 0
    transport: Optional[Dict[str, Any]] = None
    application: Optional[Dict[str, Any]] = None

@dataclass
class Receipt(Event):
    """Emitted when a message receipt is received.

    This indicates that a message has been delivered to or read by the recipient.
    """
    source: Dict[str, Any]
    message_ids: List[str]
    timestamp: datetime
    receipt_type: str
    message_sender: Optional[JID] = None

@dataclass
class ChatPresence(Event):
    """Emitted when a chat presence update is received.

    This indicates that a user's presence in a chat has changed (typing, recording, etc.).
    """
    from_jid: JID
    is_group: bool
    sender_jid: JID
    state: str
    media: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class Presence(Event):
    """Emitted when a presence update is received.

    This indicates a user's online status and last seen time.
    """
    jid: JID
    unavailable: bool = False
    last_seen: Optional[datetime] = None

@dataclass
class GroupInfo(Event):
    """Emitted when group information changes."""
    jid: JID
    notify: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    name: Optional[str] = None
    topic: Optional[Dict[str, Any]] = None
    locked: Optional[bool] = None
    announce: Optional[bool] = None
    ephemeral: Optional[int] = None
    join: List[JID] = field(default_factory=list)
    leave: List[JID] = field(default_factory=list)
    promote: List[JID] = field(default_factory=list)
    demote: List[JID] = field(default_factory=list)

@dataclass
class Picture(Event):
    """Emitted when a profile or group picture changes."""
    jid: JID
    author: JID
    timestamp: datetime
    remove: bool = False
    picture_id: Optional[str] = None

@dataclass
class PrivacySettings(Event):
    """Emitted when privacy settings change."""
    settings: Dict[str, Any]
    group_add_changed: bool = False
    last_seen_changed: bool = False
    status_changed: bool = False
    profile_changed: bool = False
    read_receipts_changed: bool = False
    online_changed: bool = False
    call_add_changed: bool = False

@dataclass
class OfflineSyncPreview(Event):
    """Emitted when receiving a preview of offline messages."""
    total: int
    app_data: Dict[str, Any]

@dataclass
class OfflineSyncCompleted(Event):
    """Emitted when offline message sync is completed."""
    count: int
    app_data: Dict[str, Any]

@dataclass
class MediaRetry(Event):
    """Emitted when media needs to be retried."""
    message_id: str
    direct_path: str
    url: str
    file_sha256: bytes
    file_enc_sha256: bytes
    media_key: bytes
    media_key_timestamp: int
    message: Dict[str, Any]

@dataclass
class Blocklist(Event):
    """Emitted when the blocklist is updated."""
    changes: Dict[JID, bool]  # JID -> blocked (True) or unblocked (False)
    dhash: str

@dataclass
class NewsletterJoin(Event):
    """Emitted when joining a newsletter."""
    id: JID
    view_role: str
    view_membership: str
    mute: str
    reactions_muted: bool
    metadata: Dict[str, Any]

@dataclass
class NewsletterLeave(Event):
    """Emitted when leaving a newsletter."""
    id: JID
    metadata: Dict[str, Any]

@dataclass
class NewsletterMuteChange(Event):
    """Emitted when a newsletter's mute state changes."""
    id: JID
    mute: str
    metadata: Dict[str, Any]

@dataclass
class NewsletterLiveUpdate(Event):
    """Emitted when a live update is received for a newsletter."""
    id: JID
    time: datetime
    message_updates: List[Dict[str, Any]]
    metadata: Dict[str, Any]

@dataclass
class NewsletterAdminMetadataUpdate(Event):
    """Emitted when a newsletter's admin metadata is updated."""
    id: JID
    metadata: Dict[str, Any]

@dataclass
class NewsletterUserMetadataUpdate(Event):
    """Emitted when a newsletter's user metadata is updated."""
    id: JID
    metadata: Dict[str, Any]

@dataclass
class NewsletterMessageUpdate(Event):
    """Emitted when a newsletter message is updated."""
    id: JID
    message_id: str
    update: Dict[str, Any]

@dataclass
class NewsletterMessageDelete(Event):
    """Emitted when a newsletter message is deleted."""
    id: JID
    message_ids: List[str]

@dataclass
class NewsletterReaction(Event):
    """Emitted when a reaction is added to a newsletter message."""
    id: JID
    message_id: str
    reaction: Optional[str]
    sender_jid: JID
    timestamp: datetime

@dataclass
class NewsletterStateChange(Event):
    """Emitted when a newsletter's state changes."""
    id: JID
    state: str
    timestamp: datetime

@dataclass
class NewsletterThreadUpdate(Event):
    """Emitted when a newsletter thread is updated."""
    id: JID
    thread_metadata: Dict[str, Any]

@dataclass
class NewsletterUpdate(Event):
    """Emitted when a newsletter is updated."""
    id: JID
    update: Dict[str, Any]

@dataclass
class NewsletterViewerMetadataUpdate(Event):
    """Emitted when a newsletter viewer's metadata is updated."""
    id: JID
    viewer_metadata: Dict[str, Any]

# Export all event classes
__all__ = [
    'Event',
    'QR',
    'PairSuccess',
    'PairError',
    'QRScannedWithoutMultidevice',
    'Connected',
    'KeepAliveTimeout',
    'KeepAliveRestored',
    'PermanentDisconnect',
    'LoggedOut',
    'StreamReplaced',
    'ManualLoginReconnect',
    'ClientOutdated',
    'CATRefreshError',
    'TempBanReason',
    'TemporaryBan',
    'ConnectFailureReason',
    'ConnectFailure',
    'StreamError',
    'Disconnected',
    'HistorySync',
    'DecryptFailMode',
    'UnavailableType',
    'UndecryptableMessage',
    'NewsletterMessageMeta',
    'Message',
    'FBMessage',
    'Receipt',
    'ChatPresence',
    'Presence',
    'GroupInfo',
    'Picture',
    'PrivacySettings',
    'OfflineSyncPreview',
    'OfflineSyncCompleted',
    'MediaRetry',
    'Blocklist',
    'NewsletterJoin',
    'NewsletterLeave',
    'NewsletterMuteChange',
    'NewsletterLiveUpdate',
    'NewsletterAdminMetadataUpdate',
    'NewsletterUserMetadataUpdate',
    'NewsletterMessageUpdate',
    'NewsletterMessageDelete',
    'NewsletterReaction',
    'NewsletterStateChange',
    'NewsletterThreadUpdate',
    'NewsletterUpdate',
    'NewsletterViewerMetadataUpdate',
]
