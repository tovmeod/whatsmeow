"""
App state events for WhatsApp.

Port of whatsmeow/types/events/appstate.go
"""
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from ...appstate import WAPatchName
from ...generated.waSyncAction import WASyncAction_pb2
from ..jid import JID
from ..message import MessageInfo
from .events import BaseEvent


@dataclass
class Contact(BaseEvent):
    """
    Emitted when an entry in the user's contact list is modified from another device.

    Port of Contact in Go.
    """
    jid: JID  # The contact who was modified
    timestamp: datetime  # The time when the modification happened

    action: Optional[WASyncAction_pb2.ContactAction] = None  # The new contact info
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class PushName(BaseEvent):
    """
    Emitted when a message is received with a different push name than the previous value cached for the same user.

    Port of PushName in Go.
    """
    jid: JID  # The user whose push name changed
    message: Optional[MessageInfo] = None  # The message where this change was first noticed
    old_push_name: str = ""  # The previous push name from the local cache
    new_push_name: str = ""  # The new push name that was included in the message


@dataclass
class BusinessName(BaseEvent):
    """
    Emitted when a message is received with a different verified business name than the previous value cached for the same user.

    Port of BusinessName in Go.
    """
    jid: JID
    message: Optional[MessageInfo] = None  # This is only present if the change was detected in a message
    old_business_name: str = ""
    new_business_name: str = ""


@dataclass
class Pin(BaseEvent):
    """
    Emitted when a chat is pinned or unpinned from another device.

    Port of Pin in Go.
    """
    jid: JID  # The chat which was pinned or unpinned
    timestamp: datetime  # The time when the (un)pinning happened

    action: Optional[WASyncAction_pb2.PinAction] = None  # Whether the chat is now pinned or not
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class Star(BaseEvent):
    """
    Emitted when a message is starred or unstarred from another device.

    Port of Star in Go.
    """
    chat_jid: JID  # The chat where the message was pinned
    is_from_me: bool  # Whether the message was sent by the user
    message_id: str  # The message which was starred or unstarred
    timestamp: datetime  # The time when the (un)starring happened
    sender_jid: Optional[JID] = None  # In group chats, the user who sent the message (except if the message was sent by the user)

    action: Optional[WASyncAction_pb2.StarAction] = None  # Whether the message is now starred or not
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class DeleteForMe(BaseEvent):
    """
    Emitted when a message is deleted (for the current user only) from another device.

    Port of DeleteForMe in Go.
    """
    chat_jid: JID  # The chat where the message was deleted
    is_from_me: bool  # Whether the message was sent by the user
    message_id: str  # The message which was deleted
    timestamp: datetime  # The time when the deletion happened
    sender_jid: Optional[JID] = None  # In group chats, the user who sent the message (except if the message was sent by the user)

    action: Optional[WASyncAction_pb2.DeleteMessageForMeAction] = None  # Additional information for the deletion
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class Mute(BaseEvent):
    """
    Emitted when a chat is muted or unmuted from another device.

    Port of Mute in Go.
    """
    jid: JID  # The chat which was muted or unmuted
    timestamp: datetime  # The time when the (un)muting happened

    action: Optional[WASyncAction_pb2.MuteAction] = None  # The current mute status of the chat
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class Archive(BaseEvent):
    """
    Emitted when a chat is archived or unarchived from another device.

    Port of Archive in Go.
    """
    jid: JID  # The chat which was archived or unarchived
    timestamp: datetime  # The time when the (un)archiving happened

    action: Optional[WASyncAction_pb2.ArchiveChatAction] = None  # The current archival status of the chat
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class MarkChatAsRead(BaseEvent):
    """
    Emitted when a whole chat is marked as read or unread from another device.

    Port of MarkChatAsRead in Go.
    """
    jid: JID  # The chat which was marked as read or unread
    timestamp: datetime  # The time when the marking happened

    action: Optional[WASyncAction_pb2.MarkChatAsReadAction] = None  # Whether the chat was marked as read or unread, and info about the most recent messages
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class ClearChat(BaseEvent):
    """
    Emitted when a chat is cleared on another device. This is different from DeleteChat.

    Port of ClearChat in Go.
    """
    jid: JID  # The chat which was cleared
    timestamp: datetime  # The time when the clear happened

    action: Optional[WASyncAction_pb2.ClearChatAction] = None  # Information about the clear
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class DeleteChat(BaseEvent):
    """
    Emitted when a chat is deleted on another device.

    Port of DeleteChat in Go.
    """
    jid: JID  # The chat which was deleted
    timestamp: datetime  # The time when the deletion happened

    action: Optional[WASyncAction_pb2.DeleteChatAction] = None  # Information about the deletion
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class PushNameSetting(BaseEvent):
    """
    Emitted when the user's push name is changed from another device.

    Port of PushNameSetting in Go.
    """
    timestamp: datetime  # The time when the push name was changed

    action: Optional[WASyncAction_pb2.PushNameSetting] = None  # The new push name for the user
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class UnarchiveChatsSetting(BaseEvent):
    """
    Emitted when the user changes the "Keep chats archived" setting from another device.

    Port of UnarchiveChatsSetting in Go.
    """
    timestamp: datetime  # The time when the setting was changed

    action: Optional[WASyncAction_pb2.UnarchiveChatsSetting] = None  # The new settings
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class UserStatusMute(BaseEvent):
    """
    Emitted when the user mutes or unmutes another user's status updates.

    Port of UserStatusMute in Go.
    """
    jid: JID  # The user who was muted or unmuted
    timestamp: datetime  # The timestamp when the action happened

    action: Optional[WASyncAction_pb2.UserStatusMuteAction] = None  # The new mute status
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class LabelEdit(BaseEvent):
    """
    Emitted when a label is edited from any device.

    Port of LabelEdit in Go.
    """
    timestamp: datetime  # The time when the label was edited
    label_id: str  # The label id which was edited

    action: Optional[WASyncAction_pb2.LabelEditAction] = None  # The new label info
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class LabelAssociationChat(BaseEvent):
    """
    Emitted when a chat is labeled or unlabeled from any device.

    Port of LabelAssociationChat in Go.
    """
    jid: JID  # The chat which was labeled or unlabeled
    timestamp: datetime  # The time when the (un)labeling happened
    label_id: str  # The label id which was added or removed

    action: Optional[WASyncAction_pb2.LabelAssociationAction] = None  # The current label status of the chat
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class LabelAssociationMessage(BaseEvent):
    """
    Emitted when a message is labeled or unlabeled from any device.

    Port of LabelAssociationMessage in Go.
    """
    jid: JID  # The chat which was labeled or unlabeled
    timestamp: datetime  # The time when the (un)labeling happened
    label_id: str  # The label id which was added or removed
    message_id: str  # The message id which was labeled or unlabeled

    action: Optional[WASyncAction_pb2.LabelAssociationAction] = None  # The current label status of the message
    from_full_sync: bool = False  # Whether the action is emitted because of a fullSync


@dataclass
class AppState(BaseEvent):
    """
    Emitted directly for new data received from app state syncing.
    You should generally use the higher-level events like events.Contact and events.Mute.

    Port of AppState in Go.
    """
    index: List[str]
    sync_action_value: Optional[WASyncAction_pb2.SyncActionValue] = None


@dataclass
class AppStateSyncComplete(BaseEvent):
    """
    Emitted when app state is resynced.

    Port of AppStateSyncComplete in Go.
    """
    name: WAPatchName
