"""
Events for WhatsApp client.

Port of whatsmeow/types/events/events.go
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol

from ...binary.node import Node
from ...generated.waArmadilloApplication import WAArmadilloApplication_pb2 as WAArm_pb2
from ...generated.waConsumerApplication import WAConsumerApplication_pb2
from ...generated.waE2E import WAWebProtobufsE2E_pb2
from ...generated.waHistorySync import WAWebProtobufsHistorySync_pb2 as WAHistorySync_pb2
from ...generated.waMsgApplication import WAMsgApplication_pb2
from ...generated.waMsgTransport import WAMsgTransport_pb2
from ...generated.waWeb import WAWebProtobufsWeb_pb2 as WAWeb_pb2
from ..jid import JID
from ..message import DeviceSentMeta, MessageID, MessageInfo, MessageSource
from ..presence import ChatPresence, ChatPresenceMedia, ReceiptType

# Deprecated: use types.ReceiptType directly
ReceiptTypeDelivered = ReceiptType.DELIVERED
ReceiptTypeSender = ReceiptType.SENDER
ReceiptTypeRetry = ReceiptType.RETRY
ReceiptTypeRead = ReceiptType.READ
ReceiptTypeReadSelf = ReceiptType.READ_SELF
ReceiptTypePlayed = ReceiptType.PLAYED

class BaseEvent:
    pass

# QR is emitted after connecting when there's no session data in the device store.
@dataclass
class QR(BaseEvent):
    """
    Emitted after connecting when there's no session data in the device store.

    The QR codes are available in the Codes list. You should render the strings as QR codes one by
    one, switching to the next one whenever enough time has passed. WhatsApp web seems to show the
    first code for 60 seconds and all other codes for 20 seconds.

    When the QR code has been scanned and pairing is complete, PairSuccess will be emitted. If you
    run out of codes before scanning, the server will close the websocket, and you will have to
    reconnect to get more codes.
    """
    codes: List[str]

# PairSuccess is emitted after the QR code has been scanned with the phone and the handshake has
# been completed.
@dataclass
class PairSuccess(BaseEvent):
    """
    Emitted after the QR code has been scanned with the phone and the handshake has been completed.

    Note that this is generally followed by a websocket reconnection, so you should
    wait for the Connected before trying to send anything.
    """
    id: JID
    lid: JID
    business_name: str
    platform: str

# PairError is emitted when a pair-success event is received from the server, but finishing the pairing locally fails.
@dataclass
class PairError(BaseEvent):
    """
    Emitted when a pair-success event is received from the server, but finishing the pairing locally fails.
    """
    id: JID
    lid: JID
    business_name: str
    platform: str
    error: Exception

# QRScannedWithoutMultidevice is emitted when the pairing QR code is scanned, but the phone didn't have multidevice enabled.
@dataclass
class QRScannedWithoutMultidevice(BaseEvent):
    """
    Emitted when the pairing QR code is scanned, but the phone didn't have multidevice enabled.

    The same QR code can still be scanned after this event, which means the user can just be told to enable multidevice and re-scan the code.
    """
    pass

# Connected is emitted when the client has successfully connected to the WhatsApp servers
# and is authenticated.
@dataclass
class Connected(BaseEvent):
    """
    Emitted when the client has successfully connected to the WhatsApp servers and is authenticated.

    The user who the client is authenticated as will be in the device store
    at this point, which is why this event doesn't contain any data.
    """
    pass

# KeepAliveTimeout is emitted when the keepalive ping request to WhatsApp web servers times out.
@dataclass
class KeepAliveTimeout(BaseEvent):
    """
    Emitted when the keepalive ping request to WhatsApp web servers times out.

    Currently, there's no automatic handling for these, but it's expected that the TCP connection will
    either start working again or notice it's dead on its own eventually. Clients may use this event to
    decide to force a disconnect+reconnect faster.
    """
    error_count: int
    last_success: datetime

# KeepAliveRestored is emitted if the keepalive pings start working again after some KeepAliveTimeout events.
@dataclass
class KeepAliveRestored(BaseEvent):
    """
    Emitted if the keepalive pings start working again after some KeepAliveTimeout events.

    Note that if the websocket disconnects before the pings start working, this event will not be emitted.
    """
    pass

# PermanentDisconnect is a class of events emitted when the client will not auto-reconnect by default.
class PermanentDisconnect(Protocol):
    """
    A class of events emitted when the client will not auto-reconnect by default.
    """
    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        pass

# TempBanReason is an error code included in temp ban error events.
class TempBanReason(Enum):
    """Error code included in temp ban error events."""
    SENT_TO_TOO_MANY_PEOPLE = 101
    BLOCKED_BY_USERS = 102
    CREATED_TOO_MANY_GROUPS = 103
    SENT_TOO_MANY_SAME_MESSAGE = 104
    BROADCAST_LIST = 106

    def __str__(self) -> str:
        """Returns the reason code and a human-readable description of the ban reason."""
        messages = {
            TempBanReason.SENT_TO_TOO_MANY_PEOPLE: "you sent too many messages to people who don't have you in their address books",
            TempBanReason.BLOCKED_BY_USERS: "too many people blocked you",
            TempBanReason.CREATED_TOO_MANY_GROUPS: "you created too many groups with people who don't have you in their address books",
            TempBanReason.SENT_TOO_MANY_SAME_MESSAGE: "you sent the same message to too many people",
            TempBanReason.BROADCAST_LIST: "you sent too many messages to a broadcast list",
        }
        msg = messages.get(self, "you may have violated the terms of service (unknown error)")
        return f"{self.value}: {msg}"

# ConnectFailureReason is an error code included in connection failure events.
class ConnectFailureReason(Enum):
    """Error code included in connection failure events."""
    GENERIC = 400
    LOGGED_OUT = 401
    TEMP_BANNED = 402
    MAIN_DEVICE_GONE = 403  # this is now called LOCKED in the whatsapp web code
    UNKNOWN_LOGOUT = 406  # this is now called BANNED in the whatsapp web code
    CLIENT_OUTDATED = 405
    BAD_USER_AGENT = 409
    CAT_EXPIRED = 413
    CAT_INVALID = 414
    NOT_FOUND = 415
    CLIENT_UNKNOWN = 418  # Status code unknown (not in WA web)
    INTERNAL_SERVER_ERROR = 500
    EXPERIMENTAL = 501
    SERVICE_UNAVAILABLE = 503

    def is_logged_out(self) -> bool:
        """Returns true if the client should delete session data due to this connect failure."""
        return self in [
            ConnectFailureReason.LOGGED_OUT,
            ConnectFailureReason.MAIN_DEVICE_GONE,
            ConnectFailureReason.UNKNOWN_LOGOUT
        ]

    def number_string(self) -> str:
        """Returns the reason code as a string."""
        return str(self.value)

    def __str__(self) -> str:
        """Returns the reason code and a short human-readable description of the error."""
        messages = {
            ConnectFailureReason.LOGGED_OUT: "logged out from another device",
            ConnectFailureReason.TEMP_BANNED: "account temporarily banned",
            ConnectFailureReason.MAIN_DEVICE_GONE: "primary device was logged out",  # seems to happen for both bans and switching phones
            ConnectFailureReason.UNKNOWN_LOGOUT: "logged out for unknown reason",
            ConnectFailureReason.CLIENT_OUTDATED: "client is out of date",
            ConnectFailureReason.BAD_USER_AGENT: "client user agent was rejected",
            ConnectFailureReason.CAT_EXPIRED: "messenger crypto auth token has expired",
            ConnectFailureReason.CAT_INVALID: "messenger crypto auth token is invalid",
        }
        msg = messages.get(self, "unknown error")
        return f"{self.value}: {msg}"

# LoggedOut is emitted when the client has been unpaired from the phone.
@dataclass
class LoggedOut(BaseEvent):
    """
    Emitted when the client has been unpaired from the phone.

    This can happen while connected (stream:error messages) or right after connecting (connect failure messages).

    This will not be emitted when the logout is initiated by this client (using Client.LogOut()).
    """
    on_connect: bool = False  # True if the event was triggered by a connect failure message
    reason: Optional[ConnectFailureReason] = None  # If on_connect is true, then this field contains the reason code

    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        if self.reason:
            return str(self.reason)
        return "logged out"

# StreamReplaced is emitted when the client is disconnected by another client connecting with the same keys.
@dataclass
class StreamReplaced(BaseEvent):
    """
    Emitted when the client is disconnected by another client connecting with the same keys.

    This can happen if you accidentally start another process with the same session
    or otherwise try to connect twice with the same session.
    """
    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        return "stream replaced"

# ManualLoginReconnect is emitted after login if DisableLoginAutoReconnect is set.
@dataclass
class ManualLoginReconnect(BaseEvent):
    """
    Emitted after login if DisableLoginAutoReconnect is set.
    """
    pass

# TemporaryBan is emitted when there's a connection failure with the ConnectFailureTempBanned reason code.
@dataclass
class TemporaryBan(BaseEvent):
    """
    Emitted when there's a connection failure with the ConnectFailureTempBanned reason code.
    """
    code: TempBanReason
    expire: Optional[timedelta] = None

    def __str__(self) -> str:
        """Returns a human-readable description of the ban."""
        if not self.expire:
            return f"You've been temporarily banned: {self.code}"
        return f"You've been temporarily banned: {self.code}. The ban expires in {self.expire}"

    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        return f"temporarily banned: {self}"

# ConnectFailure is emitted when the WhatsApp server sends a <failure> node with an unknown reason.
@dataclass
class ConnectFailure(BaseEvent):
    """
    Emitted when the WhatsApp server sends a <failure> node with an unknown reason.

    Known reasons are handled internally and emitted as different events (e.g. LoggedOut and TemporaryBan).
    """
    reason: ConnectFailureReason
    message: str
    raw: Optional[Node] = None

    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        return f"connect failure: {self.reason}"

# ClientOutdated is emitted when the WhatsApp server rejects the connection with the ConnectFailureClientOutdated code.
@dataclass
class ClientOutdated(BaseEvent):
    """
    Emitted when the WhatsApp server rejects the connection with the ConnectFailureClientOutdated code.
    """
    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        return "client outdated"

# CATRefreshError is emitted when refreshing the CAT fails.
@dataclass
class CATRefreshError:
    """
    Emitted when refreshing the CAT fails.
    """
    error: Exception

    def permanent_disconnect_description(self) -> str:
        """Returns a description of the permanent disconnect reason."""
        return "CAT refresh failed"

# StreamError is emitted when the WhatsApp server sends a <stream:error> node with an unknown code.
@dataclass
class StreamError(BaseEvent):
    """
    Emitted when the WhatsApp server sends a <stream:error> node with an unknown code.

    Known codes are handled internally and emitted as different events (e.g. LoggedOut).
    """
    code: str
    raw: Optional[Node] = None

# Disconnected is emitted when the websocket is closed by the server.
@dataclass
class Disconnected(BaseEvent):
    """
    Emitted when the websocket is closed by the server.
    """
    pass

# HistorySync is emitted when the phone has sent a blob of historical messages.
@dataclass
class HistorySync:
    """
    Emitted when the phone has sent a blob of historical messages.
    """
    data: WAHistorySync_pb2.HistorySync

class DecryptFailMode(Enum):
    """Mode for handling decryption failures."""
    SHOW = ""
    HIDE = "hide"

class UnavailableType(Enum):
    """Type of unavailable message."""
    UNKNOWN = ""
    VIEW_ONCE = "view_once"

# UndecryptableMessage is emitted when receiving a new message that failed to decrypt.
@dataclass
class UndecryptableMessage(BaseEvent):
    """
    Emitted when receiving a new message that failed to decrypt.

    The library will automatically ask the sender to retry. If the sender resends the message,
    and it's decryptable, then it will be emitted as a normal Message event.

    The UndecryptableMessage event may also be repeated if the resent message is also undecryptable.
    """
    info: MessageInfo
    is_unavailable: bool = False  # True if the recipient device didn't send a ciphertext to this device at all
    unavailable_type: UnavailableType = UnavailableType.UNKNOWN  # Some message types are intentionally unavailable
    decrypt_fail_mode: DecryptFailMode = DecryptFailMode.SHOW

# NewsletterMessageMeta contains metadata for newsletter messages.
@dataclass
class NewsletterMessageMeta:
    """
    Metadata for newsletter messages.

    When a newsletter message is edited, the message isn't wrapped in an EditedMessage like normal messages.
    Instead, the message is the new content, the ID is the original message ID, and the edit timestamp is here.
    """
    edit_ts: Optional[datetime] = None  # The edit timestamp for edited messages
    original_ts: Optional[datetime] = None  # The timestamp of the original message for edits


# Message is emitted when receiving a new message.
@dataclass
class Message:
    """
    Emitted when receiving a new message.
    """
    info: MessageInfo  # Information about the message like the chat and sender IDs
    message: Optional[WAE2E_pb2.Message] = None  # The actual message struct
    is_ephemeral: bool = False  # True if the message was unwrapped from an EphemeralMessage
    is_view_once: bool = False  # True if the message was unwrapped from a ViewOnceMessage, ViewOnceMessageV2 or ViewOnceMessageV2Extension
    is_view_once_v2: bool = False  # True if the message was unwrapped from a ViewOnceMessageV2 or ViewOnceMessageV2Extension
    is_view_once_v2_extension: bool = False  # True if the message was unwrapped from a ViewOnceMessageV2Extension
    is_document_with_caption: bool = False  # True if the message was unwrapped from a DocumentWithCaptionMessage
    is_lottie_sticker: bool = False  # True if the message was unwrapped from a LottieStickerMessage
    is_edit: bool = False  # True if the message was unwrapped from an EditedMessage
    source_web_msg: Optional[WAWeb_pb2.WebMessageInfo] = None  # If this event was parsed from a WebMessageInfo, the source data is here
    unavailable_request_id: Optional[MessageID] = None  # If this event is a response to an unavailable message request, the request ID is here
    retry_count: int = 0  # If the message was re-requested from the sender, this is the number of retries it took
    newsletter_meta: Optional[NewsletterMessageMeta] = None
    raw_message: Optional[WAE2E_pb2.Message] = None  # The raw message struct

    def unwrap_raw(self) -> 'Message':
        """
        Fills the Message, IsEphemeral, and IsViewOnce fields based on the raw message in the RawMessage field.
        """
        if not self.raw_message:
            return self

        self.message = self.raw_message

        # Handle DeviceSentMessage
        device_sent = self.message.deviceSentMessage
        if device_sent and device_sent.message:
            self.info.device_sent_meta = DeviceSentMeta(
                destination_jid=device_sent.destinationJid,
                phash=device_sent.phash,
            )
            self.message = device_sent.message

        # Handle EphemeralMessage
        ephemeral = self.message.ephemeralMessage
        if ephemeral and ephemeral.message:
            self.message = ephemeral.message
            self.is_ephemeral = True

        # Handle ViewOnceMessage
        view_once = self.message.viewOnceMessage
        if view_once and view_once.message:
            self.message = view_once.message
            self.is_view_once = True

        # Handle ViewOnceMessageV2
        view_once_v2 = self.message.viewOnceMessageV2
        if view_once_v2 and view_once_v2.message:
            self.message = view_once_v2.message
            self.is_view_once = True
            self.is_view_once_v2 = True

        # Handle ViewOnceMessageV2Extension
        view_once_v2_ext = self.message.viewOnceMessageV2Extension
        if view_once_v2_ext and view_once_v2_ext.message:
            self.message = view_once_v2_ext.message
            self.is_view_once = True
            self.is_view_once_v2 = True
            self.is_view_once_v2_extension = True

        # Handle LottieStickerMessage
        lottie = self.message.lottieStickerMessage
        if lottie and lottie.message:
            self.message = lottie.message
            self.is_lottie_sticker = True

        # Handle DocumentWithCaptionMessage
        doc_with_caption = self.message.documentWithCaptionMessage
        if doc_with_caption and doc_with_caption.message:
            self.message = doc_with_caption.message
            self.is_document_with_caption = True

        # Handle EditedMessage
        edited = self.message.editedMessage
        if edited and edited.message:
            self.message = edited.message
            self.is_edit = True

        return self

# FBMessage is emitted when receiving a new Facebook message.
@dataclass
class FBMessage:
    """
    Emitted when receiving a new Facebook message.
    """
    info: MessageInfo  # Information about the message like the chat and sender IDs
    message: Any  # The actual message struct (armadillo.MessageApplicationSub)
    retry_count: int = 0  # If the message was re-requested from the sender, this is the number of retries it took
    transport: Optional[WAMsgTransport_pb2.MessageTransport] = None  # The first level of wrapping the message was in
    application: Optional[WAMsgApplication_pb2.MessageApplication] = None  # The second level of wrapping the message was in

    def get_consumer_application(self) -> Optional[WAConsumerApplication_pb2.ConsumerApplication]:
        """
        Returns the consumer application if the message is a consumer application.
        """
        if isinstance(self.message, WAConsumerApplication_pb2.ConsumerApplication):
            return self.message
        return None

    def get_armadillo(self) -> Optional[WAArm_pb2.Armadillo]:
        """
        Returns the armadillo if the message is an armadillo.
        """
        if isinstance(self.message, WAArm_pb2.Armadillo):
            return self.message
        return None

# Receipt is emitted when an outgoing message is delivered to or read by another user, or when another device reads an incoming message.
@dataclass
class Receipt(BaseEvent):
    """
    Emitted when an outgoing message is delivered to or read by another user, or when another device reads an incoming message.

    N.B. WhatsApp on Android sends message IDs from newest message to oldest, but WhatsApp on iOS sends them in the opposite order (oldest first).
    """
    message_source: MessageSource
    message_ids: List[MessageID]
    timestamp: datetime
    type: ReceiptType  # Type of receipt (delivered, read, etc.)
    message_sender: Optional[JID] = None  # When you read the message of another user in a group, this field contains the sender of the message.
                                          # For receipts from other users, the message sender is always you.

# ChatPresence is emitted when a chat state update (also known as typing notification) is received.
@dataclass
class ChatPresenceEvent:
    """
    Emitted when a chat state update (also known as typing notification) is received.

    Note that WhatsApp won't send you these updates unless you mark yourself as online:

        client.send_presence(types.PresenceAvailable)
    """
    message_source: MessageSource
    state: ChatPresence  # The current state, either composing or paused
    media: ChatPresenceMedia  # When composing, the type of message

# Presence is emitted when a presence update is received.
@dataclass
class PresenceEvent:
    """
    Emitted when a presence update is received.

    Note that WhatsApp only sends you presence updates for individual users after you subscribe to them:

        client.subscribe_presence(user_jid)
    """
    from_jid: JID  # The user whose presence event this is
    unavailable: bool = False  # True if the user is now offline
    last_seen: Optional[datetime] = None  # The time when the user was last online

# JoinedGroup is emitted when you join or are added to a group.
@dataclass
class JoinedGroup:
    """
    Emitted when you join or are added to a group.
    """
    reason: str  # If the event was triggered by you using an invite link, this will be "invite"
    type: str  # "new" if it's a newly created group
    create_key: Optional[MessageID] = None  # If you created the group, this is the same message ID you passed to CreateGroup
    sender: Optional[JID] = None  # For type new, the user who created the group and added you to it
    sender_pn: Optional[JID] = None
    notify: str = ""
    jid: Optional[JID] = None
    name: Optional[str] = None
    topic: Optional[str] = None
    creation_time: Optional[datetime] = None
    participants: List[Dict[str, Any]] = None

# GroupInfo is emitted when the metadata of a group changes.
@dataclass
class GroupInfo:
    """
    Emitted when the metadata of a group changes.
    """
    jid: JID  # The group ID in question
    notify: str = ""  # Seems like a top-level type for the invite
    sender: Optional[JID] = None  # The user who made the change
    sender_pn: Optional[JID] = None  # The phone number of the user who made the change, if Sender is a LID
    timestamp: Optional[datetime] = None  # The time when the change occurred

    name: Optional[Any] = None  # Group name change (types.GroupName)
    topic: Optional[Any] = None  # Group topic (description) change (types.GroupTopic)
    locked: Optional[Any] = None  # Group locked status change (can only admins edit group info?) (types.GroupLocked)
    announce: Optional[Any] = None  # Group announce status change (can only admins send messages?) (types.GroupAnnounce)
    ephemeral: Optional[Any] = None  # Disappearing messages change (types.GroupEphemeral)

    membership_approval_mode: Optional[Any] = None  # Membership approval mode change (types.GroupMembershipApprovalMode)

    delete: Optional[Any] = None  # Group delete information (types.GroupDelete)

    link: Optional[Dict[str, Any]] = None
    unlink: Optional[Dict[str, Any]] = None

    new_invite_link: Optional[str] = None  # Group invite link change

    prev_participant_version_id: str = ""
    participant_version_id: str = ""

    join_reason: str = ""  # This will be "invite" if the user joined via invite link

    join: List[JID] = None  # Users who joined or were added the group
    leave: List[JID] = None  # Users who left or were removed from the group

    promote: List[JID] = None  # Users who were promoted to admins
    demote: List[JID] = None  # Users who were demoted to normal users

    unknown_changes: List[Node] = None

    def __post_init__(self):
        """Initialize empty lists."""
        if self.join is None:
            self.join = []
        if self.leave is None:
            self.leave = []
        if self.promote is None:
            self.promote = []
        if self.demote is None:
            self.demote = []
        if self.unknown_changes is None:
            self.unknown_changes = []

# Picture is emitted when a user's profile picture or group's photo is changed.
@dataclass
class Picture(BaseEvent):
    """
    Emitted when a user's profile picture or group's photo is changed.

    You can use Client.get_profile_picture_info to get the actual image URL after this event.
    """
    jid: JID  # The user or group ID where the picture was changed
    author: JID  # The user who changed the picture
    timestamp: datetime  # The timestamp when the picture was changed
    remove: bool = False  # True if the picture was removed
    picture_id: str = ""  # The new picture ID if it was not removed

# UserAbout is emitted when a user's about status is changed.
@dataclass
class UserAbout(BaseEvent):
    """
    Emitted when a user's about status is changed.
    """
    jid: JID  # The user whose status was changed
    status: str  # The new status
    timestamp: datetime  # The timestamp when the status was changed

# IdentityChange is emitted when another user changes their primary device.
@dataclass
class IdentityChange(BaseEvent):
    """
    Emitted when another user changes their primary device.
    """
    jid: JID
    timestamp: datetime
    implicit: bool = False  # True if the event was triggered by an untrusted identity error, rather than an identity change notification from the server

# PrivacySettings is emitted when the user changes their privacy settings.
@dataclass
class PrivacySettingsEvent:
    """
    Emitted when the user changes their privacy settings.
    """
    new_settings: Optional[Dict[str, Any]] = None  # types.PrivacySettings
    group_add_changed: bool = False
    last_seen_changed: bool = False
    status_changed: bool = False
    profile_changed: bool = False
    read_receipts_changed: bool = False
    online_changed: bool = False
    call_add_changed: bool = False

    def __post_init__(self):
        if self.new_settings is None:
            self.new_settings = {}

# OfflineSyncPreview is emitted right after connecting if the server is going to send events that the client missed during downtime.
@dataclass
class OfflineSyncPreview(BaseEvent):
    """
    Emitted right after connecting if the server is going to send events that the client missed during downtime.
    """
    total: int
    app_data_changes: int = 0
    messages: int = 0
    notifications: int = 0
    receipts: int = 0

# OfflineSyncCompleted is emitted after the server has finished sending missed events.
@dataclass
class OfflineSyncCompleted(BaseEvent):
    """
    Emitted after the server has finished sending missed events.
    """
    count: int

# MediaRetryError is emitted when there's an error in a media retry response.
@dataclass
class MediaRetryError:
    """
    Error in a media retry response.
    """
    code: int

# MediaRetry is emitted when the phone sends a response to a media retry request.
@dataclass
class MediaRetry(BaseEvent):
    """
    Emitted when the phone sends a response to a media retry request.
    """
    ciphertext: bytes = None
    iv: bytes = None
    error: Optional[MediaRetryError] = None  # Sometimes there's an unencrypted media retry error
    timestamp: Optional[datetime] = None  # The time of the response
    message_id: Optional[MessageID] = None  # The ID of the message
    chat_id: Optional[JID] = None  # The chat ID where the message was sent
    sender_id: Optional[JID] = None  # The user who sent the message. Only present in groups
    from_me: bool = False  # Whether the message was sent by the current user or someone else

class BlocklistAction(Enum):
    """Action for blocklist events."""
    DEFAULT = ""
    MODIFY = "modify"

class BlocklistChangeAction(Enum):
    """Action for blocklist change events."""
    BLOCK = "block"
    UNBLOCK = "unblock"

# BlocklistChange represents a change in the blocklist.
@dataclass
class BlocklistChange:
    """
    Represents a change in the blocklist.
    """
    jid: JID
    action: BlocklistChangeAction

# Blocklist is emitted when the user's blocked user list is changed.
@dataclass
class Blocklist(BaseEvent):
    """
    Emitted when the user's blocked user list is changed.
    """
    action: BlocklistAction = BlocklistAction.DEFAULT  # If it's empty, there should be a list of changes in the Changes list
    d_hash: str = ""
    prev_d_hash: str = ""
    changes: List[BlocklistChange] = None

    def __post_init__(self):
        """Initialize empty lists."""
        if self.changes is None:
            self.changes = []

# NewsletterJoin is emitted when the user joins a newsletter.
@dataclass
class NewsletterJoin(BaseEvent):
    """
    Emitted when the user joins a newsletter.
    """
    id: JID
    name: str
    picture: Optional[str] = None
    description: Optional[str] = None
    creation_time: Optional[datetime] = None
    linked_group_jid: Optional[JID] = None
    role: Optional[str] = None  # types.NewsletterRole

# NewsletterLeave is emitted when the user leaves a newsletter.
@dataclass
class NewsletterLeave(BaseEvent):
    """
    Emitted when the user leaves a newsletter.
    """
    id: JID
    role: str  # types.NewsletterRole

# NewsletterMuteChange is emitted when the user changes the mute state of a newsletter.
@dataclass
class NewsletterMuteChange(BaseEvent):
    """
    Emitted when the user changes the mute state of a newsletter.
    """
    id: JID
    mute: str  # types.NewsletterMuteState

# NewsletterLiveUpdate is emitted when there's a live update to a newsletter.
@dataclass
class NewsletterLiveUpdate(BaseEvent):
    """
    Emitted when there's a live update to a newsletter.
    """
    jid: JID
    time: datetime
    messages: List[Dict[str, Any]]  # List[*types.NewsletterMessage]

    def __post_init__(self):
        """Initialize empty lists."""
        if self.messages is None:
            self.messages = []
