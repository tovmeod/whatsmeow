"""
WhatsApp events interface.

Port of whatsmeow/types/events/
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List

from .events import (
    QR, PairSuccess, PairError, QRScannedWithoutMultidevice, Connected,
    KeepAliveTimeout, KeepAliveRestored, PermanentDisconnect, TempBanReason,
    ConnectFailureReason, LoggedOut, StreamReplaced, ManualLoginReconnect,
    TemporaryBan, ConnectFailure, ClientOutdated, CATRefreshError, StreamError,
    Disconnected, HistorySync, DecryptFailMode, UnavailableType, UndecryptableMessage,
    NewsletterMessageMeta, Message, FBMessage, Receipt, ChatPresenceEvent,
    PresenceEvent, JoinedGroup, GroupInfo, Picture, UserAbout, IdentityChange,
    PrivacySettingsEvent, OfflineSyncPreview, OfflineSyncCompleted, MediaRetryError,
    MediaRetry, BlocklistAction, BlocklistChangeAction, BlocklistChange, Blocklist,
    NewsletterJoin, NewsletterLeave, NewsletterMuteChange, NewsletterLiveUpdate
)
from .appstate import (
    WAPatchName, Contact, PushName, BusinessName, Pin, Star, DeleteForMe, Mute,
    Archive, MarkChatAsRead, ClearChat, DeleteChat, PushNameSetting,
    UnarchiveChatsSetting, UserStatusMute, LabelEdit, LabelAssociationChat,
    LabelAssociationMessage, AppState, AppStateSyncComplete
)
