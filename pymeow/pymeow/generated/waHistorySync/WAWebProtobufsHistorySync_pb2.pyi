from waSyncAction import WASyncAction_pb2 as _WASyncAction_pb2
from waChatLockSettings import WAProtobufsChatLockSettings_pb2 as _WAProtobufsChatLockSettings_pb2
from waE2E import WAWebProtobufsE2E_pb2 as _WAWebProtobufsE2E_pb2
from waCommon import WACommon_pb2 as _WACommon_pb2
from waWeb import WAWebProtobufsWeb_pb2 as _WAWebProtobufsWeb_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MediaVisibility(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEFAULT: _ClassVar[MediaVisibility]
    OFF: _ClassVar[MediaVisibility]
    ON: _ClassVar[MediaVisibility]

class PrivacySystemMessage(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    E2EE_MSG: _ClassVar[PrivacySystemMessage]
    NE2EE_SELF: _ClassVar[PrivacySystemMessage]
    NE2EE_OTHER: _ClassVar[PrivacySystemMessage]
DEFAULT: MediaVisibility
OFF: MediaVisibility
ON: MediaVisibility
E2EE_MSG: PrivacySystemMessage
NE2EE_SELF: PrivacySystemMessage
NE2EE_OTHER: PrivacySystemMessage

class HistorySync(_message.Message):
    __slots__ = ("syncType", "conversations", "statusV3Messages", "chunkOrder", "progress", "pushnames", "globalSettings", "threadIDUserSecret", "threadDsTimeframeOffset", "recentStickers", "pastParticipants", "callLogRecords", "aiWaitListState", "phoneNumberToLidMappings", "companionMetaNonce", "shareableChatIdentifierEncryptionKey", "accounts")
    class BotAIWaitListState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        IN_WAITLIST: _ClassVar[HistorySync.BotAIWaitListState]
        AI_AVAILABLE: _ClassVar[HistorySync.BotAIWaitListState]
    IN_WAITLIST: HistorySync.BotAIWaitListState
    AI_AVAILABLE: HistorySync.BotAIWaitListState
    class HistorySyncType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        INITIAL_BOOTSTRAP: _ClassVar[HistorySync.HistorySyncType]
        INITIAL_STATUS_V3: _ClassVar[HistorySync.HistorySyncType]
        FULL: _ClassVar[HistorySync.HistorySyncType]
        RECENT: _ClassVar[HistorySync.HistorySyncType]
        PUSH_NAME: _ClassVar[HistorySync.HistorySyncType]
        NON_BLOCKING_DATA: _ClassVar[HistorySync.HistorySyncType]
        ON_DEMAND: _ClassVar[HistorySync.HistorySyncType]
    INITIAL_BOOTSTRAP: HistorySync.HistorySyncType
    INITIAL_STATUS_V3: HistorySync.HistorySyncType
    FULL: HistorySync.HistorySyncType
    RECENT: HistorySync.HistorySyncType
    PUSH_NAME: HistorySync.HistorySyncType
    NON_BLOCKING_DATA: HistorySync.HistorySyncType
    ON_DEMAND: HistorySync.HistorySyncType
    SYNCTYPE_FIELD_NUMBER: _ClassVar[int]
    CONVERSATIONS_FIELD_NUMBER: _ClassVar[int]
    STATUSV3MESSAGES_FIELD_NUMBER: _ClassVar[int]
    CHUNKORDER_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    PUSHNAMES_FIELD_NUMBER: _ClassVar[int]
    GLOBALSETTINGS_FIELD_NUMBER: _ClassVar[int]
    THREADIDUSERSECRET_FIELD_NUMBER: _ClassVar[int]
    THREADDSTIMEFRAMEOFFSET_FIELD_NUMBER: _ClassVar[int]
    RECENTSTICKERS_FIELD_NUMBER: _ClassVar[int]
    PASTPARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    CALLLOGRECORDS_FIELD_NUMBER: _ClassVar[int]
    AIWAITLISTSTATE_FIELD_NUMBER: _ClassVar[int]
    PHONENUMBERTOLIDMAPPINGS_FIELD_NUMBER: _ClassVar[int]
    COMPANIONMETANONCE_FIELD_NUMBER: _ClassVar[int]
    SHAREABLECHATIDENTIFIERENCRYPTIONKEY_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTS_FIELD_NUMBER: _ClassVar[int]
    syncType: HistorySync.HistorySyncType
    conversations: _containers.RepeatedCompositeFieldContainer[Conversation]
    statusV3Messages: _containers.RepeatedCompositeFieldContainer[_WAWebProtobufsWeb_pb2.WebMessageInfo]
    chunkOrder: int
    progress: int
    pushnames: _containers.RepeatedCompositeFieldContainer[Pushname]
    globalSettings: GlobalSettings
    threadIDUserSecret: bytes
    threadDsTimeframeOffset: int
    recentStickers: _containers.RepeatedCompositeFieldContainer[StickerMetadata]
    pastParticipants: _containers.RepeatedCompositeFieldContainer[PastParticipants]
    callLogRecords: _containers.RepeatedCompositeFieldContainer[_WASyncAction_pb2.CallLogRecord]
    aiWaitListState: HistorySync.BotAIWaitListState
    phoneNumberToLidMappings: _containers.RepeatedCompositeFieldContainer[PhoneNumberToLIDMapping]
    companionMetaNonce: str
    shareableChatIdentifierEncryptionKey: bytes
    accounts: _containers.RepeatedCompositeFieldContainer[Account]
    def __init__(self, syncType: _Optional[_Union[HistorySync.HistorySyncType, str]] = ..., conversations: _Optional[_Iterable[_Union[Conversation, _Mapping]]] = ..., statusV3Messages: _Optional[_Iterable[_Union[_WAWebProtobufsWeb_pb2.WebMessageInfo, _Mapping]]] = ..., chunkOrder: _Optional[int] = ..., progress: _Optional[int] = ..., pushnames: _Optional[_Iterable[_Union[Pushname, _Mapping]]] = ..., globalSettings: _Optional[_Union[GlobalSettings, _Mapping]] = ..., threadIDUserSecret: _Optional[bytes] = ..., threadDsTimeframeOffset: _Optional[int] = ..., recentStickers: _Optional[_Iterable[_Union[StickerMetadata, _Mapping]]] = ..., pastParticipants: _Optional[_Iterable[_Union[PastParticipants, _Mapping]]] = ..., callLogRecords: _Optional[_Iterable[_Union[_WASyncAction_pb2.CallLogRecord, _Mapping]]] = ..., aiWaitListState: _Optional[_Union[HistorySync.BotAIWaitListState, str]] = ..., phoneNumberToLidMappings: _Optional[_Iterable[_Union[PhoneNumberToLIDMapping, _Mapping]]] = ..., companionMetaNonce: _Optional[str] = ..., shareableChatIdentifierEncryptionKey: _Optional[bytes] = ..., accounts: _Optional[_Iterable[_Union[Account, _Mapping]]] = ...) -> None: ...

class Conversation(_message.Message):
    __slots__ = ("ID", "messages", "newJID", "oldJID", "lastMsgTimestamp", "unreadCount", "readOnly", "endOfHistoryTransfer", "ephemeralExpiration", "ephemeralSettingTimestamp", "endOfHistoryTransferType", "conversationTimestamp", "name", "pHash", "notSpam", "archived", "disappearingMode", "unreadMentionCount", "markedAsUnread", "participant", "tcToken", "tcTokenTimestamp", "contactPrimaryIdentityKey", "pinned", "muteEndTime", "wallpaper", "mediaVisibility", "tcTokenSenderTimestamp", "suspended", "terminated", "createdAt", "createdBy", "description", "support", "isParentGroup", "parentGroupID", "isDefaultSubgroup", "displayName", "pnJID", "shareOwnPn", "pnhDuplicateLidThread", "lidJID", "username", "lidOriginType", "commentsCount", "locked", "systemMessageToInsert", "capiCreatedGroup", "accountLid", "limitSharing", "limitSharingSettingTimestamp", "limitSharingTrigger", "limitSharingInitiatedByMe")
    class EndOfHistoryTransferType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        COMPLETE_BUT_MORE_MESSAGES_REMAIN_ON_PRIMARY: _ClassVar[Conversation.EndOfHistoryTransferType]
        COMPLETE_AND_NO_MORE_MESSAGE_REMAIN_ON_PRIMARY: _ClassVar[Conversation.EndOfHistoryTransferType]
        COMPLETE_ON_DEMAND_SYNC_BUT_MORE_MSG_REMAIN_ON_PRIMARY: _ClassVar[Conversation.EndOfHistoryTransferType]
    COMPLETE_BUT_MORE_MESSAGES_REMAIN_ON_PRIMARY: Conversation.EndOfHistoryTransferType
    COMPLETE_AND_NO_MORE_MESSAGE_REMAIN_ON_PRIMARY: Conversation.EndOfHistoryTransferType
    COMPLETE_ON_DEMAND_SYNC_BUT_MORE_MSG_REMAIN_ON_PRIMARY: Conversation.EndOfHistoryTransferType
    ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    NEWJID_FIELD_NUMBER: _ClassVar[int]
    OLDJID_FIELD_NUMBER: _ClassVar[int]
    LASTMSGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    UNREADCOUNT_FIELD_NUMBER: _ClassVar[int]
    READONLY_FIELD_NUMBER: _ClassVar[int]
    ENDOFHISTORYTRANSFER_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ENDOFHISTORYTRANSFERTYPE_FIELD_NUMBER: _ClassVar[int]
    CONVERSATIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PHASH_FIELD_NUMBER: _ClassVar[int]
    NOTSPAM_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMODE_FIELD_NUMBER: _ClassVar[int]
    UNREADMENTIONCOUNT_FIELD_NUMBER: _ClassVar[int]
    MARKEDASUNREAD_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_FIELD_NUMBER: _ClassVar[int]
    TCTOKEN_FIELD_NUMBER: _ClassVar[int]
    TCTOKENTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CONTACTPRIMARYIDENTITYKEY_FIELD_NUMBER: _ClassVar[int]
    PINNED_FIELD_NUMBER: _ClassVar[int]
    MUTEENDTIME_FIELD_NUMBER: _ClassVar[int]
    WALLPAPER_FIELD_NUMBER: _ClassVar[int]
    MEDIAVISIBILITY_FIELD_NUMBER: _ClassVar[int]
    TCTOKENSENDERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SUSPENDED_FIELD_NUMBER: _ClassVar[int]
    TERMINATED_FIELD_NUMBER: _ClassVar[int]
    CREATEDAT_FIELD_NUMBER: _ClassVar[int]
    CREATEDBY_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SUPPORT_FIELD_NUMBER: _ClassVar[int]
    ISPARENTGROUP_FIELD_NUMBER: _ClassVar[int]
    PARENTGROUPID_FIELD_NUMBER: _ClassVar[int]
    ISDEFAULTSUBGROUP_FIELD_NUMBER: _ClassVar[int]
    DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
    PNJID_FIELD_NUMBER: _ClassVar[int]
    SHAREOWNPN_FIELD_NUMBER: _ClassVar[int]
    PNHDUPLICATELIDTHREAD_FIELD_NUMBER: _ClassVar[int]
    LIDJID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    LIDORIGINTYPE_FIELD_NUMBER: _ClassVar[int]
    COMMENTSCOUNT_FIELD_NUMBER: _ClassVar[int]
    LOCKED_FIELD_NUMBER: _ClassVar[int]
    SYSTEMMESSAGETOINSERT_FIELD_NUMBER: _ClassVar[int]
    CAPICREATEDGROUP_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTLID_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARING_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGTRIGGER_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGINITIATEDBYME_FIELD_NUMBER: _ClassVar[int]
    ID: str
    messages: _containers.RepeatedCompositeFieldContainer[HistorySyncMsg]
    newJID: str
    oldJID: str
    lastMsgTimestamp: int
    unreadCount: int
    readOnly: bool
    endOfHistoryTransfer: bool
    ephemeralExpiration: int
    ephemeralSettingTimestamp: int
    endOfHistoryTransferType: Conversation.EndOfHistoryTransferType
    conversationTimestamp: int
    name: str
    pHash: str
    notSpam: bool
    archived: bool
    disappearingMode: _WAWebProtobufsE2E_pb2.DisappearingMode
    unreadMentionCount: int
    markedAsUnread: bool
    participant: _containers.RepeatedCompositeFieldContainer[GroupParticipant]
    tcToken: bytes
    tcTokenTimestamp: int
    contactPrimaryIdentityKey: bytes
    pinned: int
    muteEndTime: int
    wallpaper: WallpaperSettings
    mediaVisibility: MediaVisibility
    tcTokenSenderTimestamp: int
    suspended: bool
    terminated: bool
    createdAt: int
    createdBy: str
    description: str
    support: bool
    isParentGroup: bool
    parentGroupID: str
    isDefaultSubgroup: bool
    displayName: str
    pnJID: str
    shareOwnPn: bool
    pnhDuplicateLidThread: bool
    lidJID: str
    username: str
    lidOriginType: str
    commentsCount: int
    locked: bool
    systemMessageToInsert: PrivacySystemMessage
    capiCreatedGroup: bool
    accountLid: str
    limitSharing: bool
    limitSharingSettingTimestamp: int
    limitSharingTrigger: _WACommon_pb2.LimitSharing.Trigger
    limitSharingInitiatedByMe: bool
    def __init__(self, ID: _Optional[str] = ..., messages: _Optional[_Iterable[_Union[HistorySyncMsg, _Mapping]]] = ..., newJID: _Optional[str] = ..., oldJID: _Optional[str] = ..., lastMsgTimestamp: _Optional[int] = ..., unreadCount: _Optional[int] = ..., readOnly: bool = ..., endOfHistoryTransfer: bool = ..., ephemeralExpiration: _Optional[int] = ..., ephemeralSettingTimestamp: _Optional[int] = ..., endOfHistoryTransferType: _Optional[_Union[Conversation.EndOfHistoryTransferType, str]] = ..., conversationTimestamp: _Optional[int] = ..., name: _Optional[str] = ..., pHash: _Optional[str] = ..., notSpam: bool = ..., archived: bool = ..., disappearingMode: _Optional[_Union[_WAWebProtobufsE2E_pb2.DisappearingMode, _Mapping]] = ..., unreadMentionCount: _Optional[int] = ..., markedAsUnread: bool = ..., participant: _Optional[_Iterable[_Union[GroupParticipant, _Mapping]]] = ..., tcToken: _Optional[bytes] = ..., tcTokenTimestamp: _Optional[int] = ..., contactPrimaryIdentityKey: _Optional[bytes] = ..., pinned: _Optional[int] = ..., muteEndTime: _Optional[int] = ..., wallpaper: _Optional[_Union[WallpaperSettings, _Mapping]] = ..., mediaVisibility: _Optional[_Union[MediaVisibility, str]] = ..., tcTokenSenderTimestamp: _Optional[int] = ..., suspended: bool = ..., terminated: bool = ..., createdAt: _Optional[int] = ..., createdBy: _Optional[str] = ..., description: _Optional[str] = ..., support: bool = ..., isParentGroup: bool = ..., parentGroupID: _Optional[str] = ..., isDefaultSubgroup: bool = ..., displayName: _Optional[str] = ..., pnJID: _Optional[str] = ..., shareOwnPn: bool = ..., pnhDuplicateLidThread: bool = ..., lidJID: _Optional[str] = ..., username: _Optional[str] = ..., lidOriginType: _Optional[str] = ..., commentsCount: _Optional[int] = ..., locked: bool = ..., systemMessageToInsert: _Optional[_Union[PrivacySystemMessage, str]] = ..., capiCreatedGroup: bool = ..., accountLid: _Optional[str] = ..., limitSharing: bool = ..., limitSharingSettingTimestamp: _Optional[int] = ..., limitSharingTrigger: _Optional[_Union[_WACommon_pb2.LimitSharing.Trigger, str]] = ..., limitSharingInitiatedByMe: bool = ...) -> None: ...

class GroupParticipant(_message.Message):
    __slots__ = ("userJID", "rank")
    class Rank(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REGULAR: _ClassVar[GroupParticipant.Rank]
        ADMIN: _ClassVar[GroupParticipant.Rank]
        SUPERADMIN: _ClassVar[GroupParticipant.Rank]
    REGULAR: GroupParticipant.Rank
    ADMIN: GroupParticipant.Rank
    SUPERADMIN: GroupParticipant.Rank
    USERJID_FIELD_NUMBER: _ClassVar[int]
    RANK_FIELD_NUMBER: _ClassVar[int]
    userJID: str
    rank: GroupParticipant.Rank
    def __init__(self, userJID: _Optional[str] = ..., rank: _Optional[_Union[GroupParticipant.Rank, str]] = ...) -> None: ...

class PastParticipant(_message.Message):
    __slots__ = ("userJID", "leaveReason", "leaveTS")
    class LeaveReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LEFT: _ClassVar[PastParticipant.LeaveReason]
        REMOVED: _ClassVar[PastParticipant.LeaveReason]
    LEFT: PastParticipant.LeaveReason
    REMOVED: PastParticipant.LeaveReason
    USERJID_FIELD_NUMBER: _ClassVar[int]
    LEAVEREASON_FIELD_NUMBER: _ClassVar[int]
    LEAVETS_FIELD_NUMBER: _ClassVar[int]
    userJID: str
    leaveReason: PastParticipant.LeaveReason
    leaveTS: int
    def __init__(self, userJID: _Optional[str] = ..., leaveReason: _Optional[_Union[PastParticipant.LeaveReason, str]] = ..., leaveTS: _Optional[int] = ...) -> None: ...

class PhoneNumberToLIDMapping(_message.Message):
    __slots__ = ("pnJID", "lidJID")
    PNJID_FIELD_NUMBER: _ClassVar[int]
    LIDJID_FIELD_NUMBER: _ClassVar[int]
    pnJID: str
    lidJID: str
    def __init__(self, pnJID: _Optional[str] = ..., lidJID: _Optional[str] = ...) -> None: ...

class Account(_message.Message):
    __slots__ = ("lid", "username", "countryCode", "isUsernameDeleted")
    LID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    COUNTRYCODE_FIELD_NUMBER: _ClassVar[int]
    ISUSERNAMEDELETED_FIELD_NUMBER: _ClassVar[int]
    lid: str
    username: str
    countryCode: str
    isUsernameDeleted: bool
    def __init__(self, lid: _Optional[str] = ..., username: _Optional[str] = ..., countryCode: _Optional[str] = ..., isUsernameDeleted: bool = ...) -> None: ...

class HistorySyncMsg(_message.Message):
    __slots__ = ("message", "msgOrderID")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MSGORDERID_FIELD_NUMBER: _ClassVar[int]
    message: _WAWebProtobufsWeb_pb2.WebMessageInfo
    msgOrderID: int
    def __init__(self, message: _Optional[_Union[_WAWebProtobufsWeb_pb2.WebMessageInfo, _Mapping]] = ..., msgOrderID: _Optional[int] = ...) -> None: ...

class Pushname(_message.Message):
    __slots__ = ("ID", "pushname")
    ID_FIELD_NUMBER: _ClassVar[int]
    PUSHNAME_FIELD_NUMBER: _ClassVar[int]
    ID: str
    pushname: str
    def __init__(self, ID: _Optional[str] = ..., pushname: _Optional[str] = ...) -> None: ...

class WallpaperSettings(_message.Message):
    __slots__ = ("filename", "opacity")
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    OPACITY_FIELD_NUMBER: _ClassVar[int]
    filename: str
    opacity: int
    def __init__(self, filename: _Optional[str] = ..., opacity: _Optional[int] = ...) -> None: ...

class GlobalSettings(_message.Message):
    __slots__ = ("lightThemeWallpaper", "mediaVisibility", "darkThemeWallpaper", "autoDownloadWiFi", "autoDownloadCellular", "autoDownloadRoaming", "showIndividualNotificationsPreview", "showGroupNotificationsPreview", "disappearingModeDuration", "disappearingModeTimestamp", "avatarUserSettings", "fontSize", "securityNotifications", "autoUnarchiveChats", "videoQualityMode", "photoQualityMode", "individualNotificationSettings", "groupNotificationSettings", "chatLockSettings", "chatDbLidMigrationTimestamp")
    LIGHTTHEMEWALLPAPER_FIELD_NUMBER: _ClassVar[int]
    MEDIAVISIBILITY_FIELD_NUMBER: _ClassVar[int]
    DARKTHEMEWALLPAPER_FIELD_NUMBER: _ClassVar[int]
    AUTODOWNLOADWIFI_FIELD_NUMBER: _ClassVar[int]
    AUTODOWNLOADCELLULAR_FIELD_NUMBER: _ClassVar[int]
    AUTODOWNLOADROAMING_FIELD_NUMBER: _ClassVar[int]
    SHOWINDIVIDUALNOTIFICATIONSPREVIEW_FIELD_NUMBER: _ClassVar[int]
    SHOWGROUPNOTIFICATIONSPREVIEW_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMODEDURATION_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMODETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    AVATARUSERSETTINGS_FIELD_NUMBER: _ClassVar[int]
    FONTSIZE_FIELD_NUMBER: _ClassVar[int]
    SECURITYNOTIFICATIONS_FIELD_NUMBER: _ClassVar[int]
    AUTOUNARCHIVECHATS_FIELD_NUMBER: _ClassVar[int]
    VIDEOQUALITYMODE_FIELD_NUMBER: _ClassVar[int]
    PHOTOQUALITYMODE_FIELD_NUMBER: _ClassVar[int]
    INDIVIDUALNOTIFICATIONSETTINGS_FIELD_NUMBER: _ClassVar[int]
    GROUPNOTIFICATIONSETTINGS_FIELD_NUMBER: _ClassVar[int]
    CHATLOCKSETTINGS_FIELD_NUMBER: _ClassVar[int]
    CHATDBLIDMIGRATIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    lightThemeWallpaper: WallpaperSettings
    mediaVisibility: MediaVisibility
    darkThemeWallpaper: WallpaperSettings
    autoDownloadWiFi: AutoDownloadSettings
    autoDownloadCellular: AutoDownloadSettings
    autoDownloadRoaming: AutoDownloadSettings
    showIndividualNotificationsPreview: bool
    showGroupNotificationsPreview: bool
    disappearingModeDuration: int
    disappearingModeTimestamp: int
    avatarUserSettings: AvatarUserSettings
    fontSize: int
    securityNotifications: bool
    autoUnarchiveChats: bool
    videoQualityMode: int
    photoQualityMode: int
    individualNotificationSettings: NotificationSettings
    groupNotificationSettings: NotificationSettings
    chatLockSettings: _WAProtobufsChatLockSettings_pb2.ChatLockSettings
    chatDbLidMigrationTimestamp: int
    def __init__(self, lightThemeWallpaper: _Optional[_Union[WallpaperSettings, _Mapping]] = ..., mediaVisibility: _Optional[_Union[MediaVisibility, str]] = ..., darkThemeWallpaper: _Optional[_Union[WallpaperSettings, _Mapping]] = ..., autoDownloadWiFi: _Optional[_Union[AutoDownloadSettings, _Mapping]] = ..., autoDownloadCellular: _Optional[_Union[AutoDownloadSettings, _Mapping]] = ..., autoDownloadRoaming: _Optional[_Union[AutoDownloadSettings, _Mapping]] = ..., showIndividualNotificationsPreview: bool = ..., showGroupNotificationsPreview: bool = ..., disappearingModeDuration: _Optional[int] = ..., disappearingModeTimestamp: _Optional[int] = ..., avatarUserSettings: _Optional[_Union[AvatarUserSettings, _Mapping]] = ..., fontSize: _Optional[int] = ..., securityNotifications: bool = ..., autoUnarchiveChats: bool = ..., videoQualityMode: _Optional[int] = ..., photoQualityMode: _Optional[int] = ..., individualNotificationSettings: _Optional[_Union[NotificationSettings, _Mapping]] = ..., groupNotificationSettings: _Optional[_Union[NotificationSettings, _Mapping]] = ..., chatLockSettings: _Optional[_Union[_WAProtobufsChatLockSettings_pb2.ChatLockSettings, _Mapping]] = ..., chatDbLidMigrationTimestamp: _Optional[int] = ...) -> None: ...

class AutoDownloadSettings(_message.Message):
    __slots__ = ("downloadImages", "downloadAudio", "downloadVideo", "downloadDocuments")
    DOWNLOADIMAGES_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADAUDIO_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADVIDEO_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADDOCUMENTS_FIELD_NUMBER: _ClassVar[int]
    downloadImages: bool
    downloadAudio: bool
    downloadVideo: bool
    downloadDocuments: bool
    def __init__(self, downloadImages: bool = ..., downloadAudio: bool = ..., downloadVideo: bool = ..., downloadDocuments: bool = ...) -> None: ...

class StickerMetadata(_message.Message):
    __slots__ = ("URL", "fileSHA256", "fileEncSHA256", "mediaKey", "mimetype", "height", "width", "directPath", "fileLength", "weight", "lastStickerSentTS", "isLottie")
    URL_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    WEIGHT_FIELD_NUMBER: _ClassVar[int]
    LASTSTICKERSENTTS_FIELD_NUMBER: _ClassVar[int]
    ISLOTTIE_FIELD_NUMBER: _ClassVar[int]
    URL: str
    fileSHA256: bytes
    fileEncSHA256: bytes
    mediaKey: bytes
    mimetype: str
    height: int
    width: int
    directPath: str
    fileLength: int
    weight: float
    lastStickerSentTS: int
    isLottie: bool
    def __init__(self, URL: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., mimetype: _Optional[str] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., directPath: _Optional[str] = ..., fileLength: _Optional[int] = ..., weight: _Optional[float] = ..., lastStickerSentTS: _Optional[int] = ..., isLottie: bool = ...) -> None: ...

class PastParticipants(_message.Message):
    __slots__ = ("groupJID", "pastParticipants")
    GROUPJID_FIELD_NUMBER: _ClassVar[int]
    PASTPARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    groupJID: str
    pastParticipants: _containers.RepeatedCompositeFieldContainer[PastParticipant]
    def __init__(self, groupJID: _Optional[str] = ..., pastParticipants: _Optional[_Iterable[_Union[PastParticipant, _Mapping]]] = ...) -> None: ...

class AvatarUserSettings(_message.Message):
    __slots__ = ("FBID", "password")
    FBID_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    FBID: str
    password: str
    def __init__(self, FBID: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class NotificationSettings(_message.Message):
    __slots__ = ("messageVibrate", "messagePopup", "messageLight", "lowPriorityNotifications", "reactionsMuted", "callVibrate")
    MESSAGEVIBRATE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEPOPUP_FIELD_NUMBER: _ClassVar[int]
    MESSAGELIGHT_FIELD_NUMBER: _ClassVar[int]
    LOWPRIORITYNOTIFICATIONS_FIELD_NUMBER: _ClassVar[int]
    REACTIONSMUTED_FIELD_NUMBER: _ClassVar[int]
    CALLVIBRATE_FIELD_NUMBER: _ClassVar[int]
    messageVibrate: str
    messagePopup: str
    messageLight: str
    lowPriorityNotifications: bool
    reactionsMuted: bool
    callVibrate: str
    def __init__(self, messageVibrate: _Optional[str] = ..., messagePopup: _Optional[str] = ..., messageLight: _Optional[str] = ..., lowPriorityNotifications: bool = ..., reactionsMuted: bool = ..., callVibrate: _Optional[str] = ...) -> None: ...
