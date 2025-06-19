from waAdv import WAAdv_pb2 as _WAAdv_pb2
from waCompanionReg import WACompanionReg_pb2 as _WACompanionReg_pb2
from waMmsRetry import WAMmsRetry_pb2 as _WAMmsRetry_pb2
from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PollContentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN_POLL_CONTENT_TYPE: _ClassVar[PollContentType]
    TEXT: _ClassVar[PollContentType]
    IMAGE: _ClassVar[PollContentType]

class PeerDataOperationRequestType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UPLOAD_STICKER: _ClassVar[PeerDataOperationRequestType]
    SEND_RECENT_STICKER_BOOTSTRAP: _ClassVar[PeerDataOperationRequestType]
    GENERATE_LINK_PREVIEW: _ClassVar[PeerDataOperationRequestType]
    HISTORY_SYNC_ON_DEMAND: _ClassVar[PeerDataOperationRequestType]
    PLACEHOLDER_MESSAGE_RESEND: _ClassVar[PeerDataOperationRequestType]
    WAFFLE_LINKING_NONCE_FETCH: _ClassVar[PeerDataOperationRequestType]
    FULL_HISTORY_SYNC_ON_DEMAND: _ClassVar[PeerDataOperationRequestType]
    COMPANION_META_NONCE_FETCH: _ClassVar[PeerDataOperationRequestType]
    COMPANION_SYNCD_SNAPSHOT_FATAL_RECOVERY: _ClassVar[PeerDataOperationRequestType]

class BotMetricsEntryPoint(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FAVICON: _ClassVar[BotMetricsEntryPoint]
    CHATLIST: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_NULL_STATE_PAPER_PLANE: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_NULL_STATE_SUGGESTION: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_TYPE_AHEAD_SUGGESTION: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_TYPE_AHEAD_PAPER_PLANE: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_TYPE_AHEAD_RESULT_CHATLIST: _ClassVar[BotMetricsEntryPoint]
    AISEARCH_TYPE_AHEAD_RESULT_MESSAGES: _ClassVar[BotMetricsEntryPoint]
    AIVOICE_SEARCH_BAR: _ClassVar[BotMetricsEntryPoint]
    AIVOICE_FAVICON: _ClassVar[BotMetricsEntryPoint]
    AISTUDIO: _ClassVar[BotMetricsEntryPoint]
    DEEPLINK: _ClassVar[BotMetricsEntryPoint]
    NOTIFICATION: _ClassVar[BotMetricsEntryPoint]
    PROFILE_MESSAGE_BUTTON: _ClassVar[BotMetricsEntryPoint]
    FORWARD: _ClassVar[BotMetricsEntryPoint]
    APP_SHORTCUT: _ClassVar[BotMetricsEntryPoint]
    FF_FAMILY: _ClassVar[BotMetricsEntryPoint]
    AI_TAB: _ClassVar[BotMetricsEntryPoint]
    AI_HOME: _ClassVar[BotMetricsEntryPoint]
    AI_DEEPLINK_IMMERSIVE: _ClassVar[BotMetricsEntryPoint]
    AI_DEEPLINK: _ClassVar[BotMetricsEntryPoint]
    META_AI_CHAT_SHORTCUT_AI_STUDIO: _ClassVar[BotMetricsEntryPoint]
    UGC_CHAT_SHORTCUT_AI_STUDIO: _ClassVar[BotMetricsEntryPoint]
    NEW_CHAT_AI_STUDIO: _ClassVar[BotMetricsEntryPoint]

class BotMetricsThreadEntryPoint(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AI_TAB_THREAD: _ClassVar[BotMetricsThreadEntryPoint]
    AI_HOME_THREAD: _ClassVar[BotMetricsThreadEntryPoint]
    AI_DEEPLINK_IMMERSIVE_THREAD: _ClassVar[BotMetricsThreadEntryPoint]
    AI_DEEPLINK_THREAD: _ClassVar[BotMetricsThreadEntryPoint]

class BotSessionSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NONE: _ClassVar[BotSessionSource]
    NULL_STATE: _ClassVar[BotSessionSource]
    TYPEAHEAD: _ClassVar[BotSessionSource]
    USER_INPUT: _ClassVar[BotSessionSource]
    EMU_FLASH: _ClassVar[BotSessionSource]
    EMU_FLASH_FOLLOWUP: _ClassVar[BotSessionSource]
    VOICE: _ClassVar[BotSessionSource]

class KeepType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN_KEEP_TYPE: _ClassVar[KeepType]
    KEEP_FOR_ALL: _ClassVar[KeepType]
    UNDO_KEEP_FOR_ALL: _ClassVar[KeepType]
UNKNOWN_POLL_CONTENT_TYPE: PollContentType
TEXT: PollContentType
IMAGE: PollContentType
UPLOAD_STICKER: PeerDataOperationRequestType
SEND_RECENT_STICKER_BOOTSTRAP: PeerDataOperationRequestType
GENERATE_LINK_PREVIEW: PeerDataOperationRequestType
HISTORY_SYNC_ON_DEMAND: PeerDataOperationRequestType
PLACEHOLDER_MESSAGE_RESEND: PeerDataOperationRequestType
WAFFLE_LINKING_NONCE_FETCH: PeerDataOperationRequestType
FULL_HISTORY_SYNC_ON_DEMAND: PeerDataOperationRequestType
COMPANION_META_NONCE_FETCH: PeerDataOperationRequestType
COMPANION_SYNCD_SNAPSHOT_FATAL_RECOVERY: PeerDataOperationRequestType
FAVICON: BotMetricsEntryPoint
CHATLIST: BotMetricsEntryPoint
AISEARCH_NULL_STATE_PAPER_PLANE: BotMetricsEntryPoint
AISEARCH_NULL_STATE_SUGGESTION: BotMetricsEntryPoint
AISEARCH_TYPE_AHEAD_SUGGESTION: BotMetricsEntryPoint
AISEARCH_TYPE_AHEAD_PAPER_PLANE: BotMetricsEntryPoint
AISEARCH_TYPE_AHEAD_RESULT_CHATLIST: BotMetricsEntryPoint
AISEARCH_TYPE_AHEAD_RESULT_MESSAGES: BotMetricsEntryPoint
AIVOICE_SEARCH_BAR: BotMetricsEntryPoint
AIVOICE_FAVICON: BotMetricsEntryPoint
AISTUDIO: BotMetricsEntryPoint
DEEPLINK: BotMetricsEntryPoint
NOTIFICATION: BotMetricsEntryPoint
PROFILE_MESSAGE_BUTTON: BotMetricsEntryPoint
FORWARD: BotMetricsEntryPoint
APP_SHORTCUT: BotMetricsEntryPoint
FF_FAMILY: BotMetricsEntryPoint
AI_TAB: BotMetricsEntryPoint
AI_HOME: BotMetricsEntryPoint
AI_DEEPLINK_IMMERSIVE: BotMetricsEntryPoint
AI_DEEPLINK: BotMetricsEntryPoint
META_AI_CHAT_SHORTCUT_AI_STUDIO: BotMetricsEntryPoint
UGC_CHAT_SHORTCUT_AI_STUDIO: BotMetricsEntryPoint
NEW_CHAT_AI_STUDIO: BotMetricsEntryPoint
AI_TAB_THREAD: BotMetricsThreadEntryPoint
AI_HOME_THREAD: BotMetricsThreadEntryPoint
AI_DEEPLINK_IMMERSIVE_THREAD: BotMetricsThreadEntryPoint
AI_DEEPLINK_THREAD: BotMetricsThreadEntryPoint
NONE: BotSessionSource
NULL_STATE: BotSessionSource
TYPEAHEAD: BotSessionSource
USER_INPUT: BotSessionSource
EMU_FLASH: BotSessionSource
EMU_FLASH_FOLLOWUP: BotSessionSource
VOICE: BotSessionSource
UNKNOWN_KEEP_TYPE: KeepType
KEEP_FOR_ALL: KeepType
UNDO_KEEP_FOR_ALL: KeepType

class StickerPackMessage(_message.Message):
    __slots__ = ("stickerPackID", "name", "publisher", "stickers", "fileLength", "fileSHA256", "fileEncSHA256", "mediaKey", "directPath", "caption", "contextInfo", "packDescription", "mediaKeyTimestamp", "trayIconFileName", "thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "thumbnailHeight", "thumbnailWidth", "imageDataHash", "stickerPackSize", "stickerPackOrigin")
    class StickerPackOrigin(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        FIRST_PARTY: _ClassVar[StickerPackMessage.StickerPackOrigin]
        THIRD_PARTY: _ClassVar[StickerPackMessage.StickerPackOrigin]
        USER_CREATED: _ClassVar[StickerPackMessage.StickerPackOrigin]
    FIRST_PARTY: StickerPackMessage.StickerPackOrigin
    THIRD_PARTY: StickerPackMessage.StickerPackOrigin
    USER_CREATED: StickerPackMessage.StickerPackOrigin
    class Sticker(_message.Message):
        __slots__ = ("fileName", "isAnimated", "emojis", "accessibilityLabel", "isLottie", "mimetype")
        FILENAME_FIELD_NUMBER: _ClassVar[int]
        ISANIMATED_FIELD_NUMBER: _ClassVar[int]
        EMOJIS_FIELD_NUMBER: _ClassVar[int]
        ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
        ISLOTTIE_FIELD_NUMBER: _ClassVar[int]
        MIMETYPE_FIELD_NUMBER: _ClassVar[int]
        fileName: str
        isAnimated: bool
        emojis: _containers.RepeatedScalarFieldContainer[str]
        accessibilityLabel: str
        isLottie: bool
        mimetype: str
        def __init__(self, fileName: _Optional[str] = ..., isAnimated: bool = ..., emojis: _Optional[_Iterable[str]] = ..., accessibilityLabel: _Optional[str] = ..., isLottie: bool = ..., mimetype: _Optional[str] = ...) -> None: ...
    STICKERPACKID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PUBLISHER_FIELD_NUMBER: _ClassVar[int]
    STICKERS_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    PACKDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    TRAYICONFILENAME_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILHEIGHT_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILWIDTH_FIELD_NUMBER: _ClassVar[int]
    IMAGEDATAHASH_FIELD_NUMBER: _ClassVar[int]
    STICKERPACKSIZE_FIELD_NUMBER: _ClassVar[int]
    STICKERPACKORIGIN_FIELD_NUMBER: _ClassVar[int]
    stickerPackID: str
    name: str
    publisher: str
    stickers: _containers.RepeatedCompositeFieldContainer[StickerPackMessage.Sticker]
    fileLength: int
    fileSHA256: bytes
    fileEncSHA256: bytes
    mediaKey: bytes
    directPath: str
    caption: str
    contextInfo: ContextInfo
    packDescription: str
    mediaKeyTimestamp: int
    trayIconFileName: str
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    thumbnailHeight: int
    thumbnailWidth: int
    imageDataHash: str
    stickerPackSize: int
    stickerPackOrigin: StickerPackMessage.StickerPackOrigin
    def __init__(self, stickerPackID: _Optional[str] = ..., name: _Optional[str] = ..., publisher: _Optional[str] = ..., stickers: _Optional[_Iterable[_Union[StickerPackMessage.Sticker, _Mapping]]] = ..., fileLength: _Optional[int] = ..., fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., directPath: _Optional[str] = ..., caption: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., packDescription: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., trayIconFileName: _Optional[str] = ..., thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., thumbnailHeight: _Optional[int] = ..., thumbnailWidth: _Optional[int] = ..., imageDataHash: _Optional[str] = ..., stickerPackSize: _Optional[int] = ..., stickerPackOrigin: _Optional[_Union[StickerPackMessage.StickerPackOrigin, str]] = ...) -> None: ...

class PlaceholderMessage(_message.Message):
    __slots__ = ("type",)
    class PlaceholderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        MASK_LINKED_DEVICES: _ClassVar[PlaceholderMessage.PlaceholderType]
    MASK_LINKED_DEVICES: PlaceholderMessage.PlaceholderType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: PlaceholderMessage.PlaceholderType
    def __init__(self, type: _Optional[_Union[PlaceholderMessage.PlaceholderType, str]] = ...) -> None: ...

class BCallMessage(_message.Message):
    __slots__ = ("sessionID", "mediaType", "masterKey", "caption")
    class MediaType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[BCallMessage.MediaType]
        AUDIO: _ClassVar[BCallMessage.MediaType]
        VIDEO: _ClassVar[BCallMessage.MediaType]
    UNKNOWN: BCallMessage.MediaType
    AUDIO: BCallMessage.MediaType
    VIDEO: BCallMessage.MediaType
    SESSIONID_FIELD_NUMBER: _ClassVar[int]
    MEDIATYPE_FIELD_NUMBER: _ClassVar[int]
    MASTERKEY_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    sessionID: str
    mediaType: BCallMessage.MediaType
    masterKey: bytes
    caption: str
    def __init__(self, sessionID: _Optional[str] = ..., mediaType: _Optional[_Union[BCallMessage.MediaType, str]] = ..., masterKey: _Optional[bytes] = ..., caption: _Optional[str] = ...) -> None: ...

class CallLogMessage(_message.Message):
    __slots__ = ("isVideo", "callOutcome", "durationSecs", "callType", "participants")
    class CallOutcome(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CONNECTED: _ClassVar[CallLogMessage.CallOutcome]
        MISSED: _ClassVar[CallLogMessage.CallOutcome]
        FAILED: _ClassVar[CallLogMessage.CallOutcome]
        REJECTED: _ClassVar[CallLogMessage.CallOutcome]
        ACCEPTED_ELSEWHERE: _ClassVar[CallLogMessage.CallOutcome]
        ONGOING: _ClassVar[CallLogMessage.CallOutcome]
        SILENCED_BY_DND: _ClassVar[CallLogMessage.CallOutcome]
        SILENCED_UNKNOWN_CALLER: _ClassVar[CallLogMessage.CallOutcome]
    CONNECTED: CallLogMessage.CallOutcome
    MISSED: CallLogMessage.CallOutcome
    FAILED: CallLogMessage.CallOutcome
    REJECTED: CallLogMessage.CallOutcome
    ACCEPTED_ELSEWHERE: CallLogMessage.CallOutcome
    ONGOING: CallLogMessage.CallOutcome
    SILENCED_BY_DND: CallLogMessage.CallOutcome
    SILENCED_UNKNOWN_CALLER: CallLogMessage.CallOutcome
    class CallType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REGULAR: _ClassVar[CallLogMessage.CallType]
        SCHEDULED_CALL: _ClassVar[CallLogMessage.CallType]
        VOICE_CHAT: _ClassVar[CallLogMessage.CallType]
    REGULAR: CallLogMessage.CallType
    SCHEDULED_CALL: CallLogMessage.CallType
    VOICE_CHAT: CallLogMessage.CallType
    class CallParticipant(_message.Message):
        __slots__ = ("JID", "callOutcome")
        JID_FIELD_NUMBER: _ClassVar[int]
        CALLOUTCOME_FIELD_NUMBER: _ClassVar[int]
        JID: str
        callOutcome: CallLogMessage.CallOutcome
        def __init__(self, JID: _Optional[str] = ..., callOutcome: _Optional[_Union[CallLogMessage.CallOutcome, str]] = ...) -> None: ...
    ISVIDEO_FIELD_NUMBER: _ClassVar[int]
    CALLOUTCOME_FIELD_NUMBER: _ClassVar[int]
    DURATIONSECS_FIELD_NUMBER: _ClassVar[int]
    CALLTYPE_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    isVideo: bool
    callOutcome: CallLogMessage.CallOutcome
    durationSecs: int
    callType: CallLogMessage.CallType
    participants: _containers.RepeatedCompositeFieldContainer[CallLogMessage.CallParticipant]
    def __init__(self, isVideo: bool = ..., callOutcome: _Optional[_Union[CallLogMessage.CallOutcome, str]] = ..., durationSecs: _Optional[int] = ..., callType: _Optional[_Union[CallLogMessage.CallType, str]] = ..., participants: _Optional[_Iterable[_Union[CallLogMessage.CallParticipant, _Mapping]]] = ...) -> None: ...

class ScheduledCallEditMessage(_message.Message):
    __slots__ = ("key", "editType")
    class EditType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ScheduledCallEditMessage.EditType]
        CANCEL: _ClassVar[ScheduledCallEditMessage.EditType]
    UNKNOWN: ScheduledCallEditMessage.EditType
    CANCEL: ScheduledCallEditMessage.EditType
    KEY_FIELD_NUMBER: _ClassVar[int]
    EDITTYPE_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    editType: ScheduledCallEditMessage.EditType
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., editType: _Optional[_Union[ScheduledCallEditMessage.EditType, str]] = ...) -> None: ...

class ScheduledCallCreationMessage(_message.Message):
    __slots__ = ("scheduledTimestampMS", "callType", "title")
    class CallType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ScheduledCallCreationMessage.CallType]
        VOICE: _ClassVar[ScheduledCallCreationMessage.CallType]
        VIDEO: _ClassVar[ScheduledCallCreationMessage.CallType]
    UNKNOWN: ScheduledCallCreationMessage.CallType
    VOICE: ScheduledCallCreationMessage.CallType
    VIDEO: ScheduledCallCreationMessage.CallType
    SCHEDULEDTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    CALLTYPE_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    scheduledTimestampMS: int
    callType: ScheduledCallCreationMessage.CallType
    title: str
    def __init__(self, scheduledTimestampMS: _Optional[int] = ..., callType: _Optional[_Union[ScheduledCallCreationMessage.CallType, str]] = ..., title: _Optional[str] = ...) -> None: ...

class EventResponseMessage(_message.Message):
    __slots__ = ("response", "timestampMS", "extraGuestCount")
    class EventResponseType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[EventResponseMessage.EventResponseType]
        GOING: _ClassVar[EventResponseMessage.EventResponseType]
        NOT_GOING: _ClassVar[EventResponseMessage.EventResponseType]
        MAYBE: _ClassVar[EventResponseMessage.EventResponseType]
    UNKNOWN: EventResponseMessage.EventResponseType
    GOING: EventResponseMessage.EventResponseType
    NOT_GOING: EventResponseMessage.EventResponseType
    MAYBE: EventResponseMessage.EventResponseType
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    EXTRAGUESTCOUNT_FIELD_NUMBER: _ClassVar[int]
    response: EventResponseMessage.EventResponseType
    timestampMS: int
    extraGuestCount: int
    def __init__(self, response: _Optional[_Union[EventResponseMessage.EventResponseType, str]] = ..., timestampMS: _Optional[int] = ..., extraGuestCount: _Optional[int] = ...) -> None: ...

class PinInChatMessage(_message.Message):
    __slots__ = ("key", "type", "senderTimestampMS")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_TYPE: _ClassVar[PinInChatMessage.Type]
        PIN_FOR_ALL: _ClassVar[PinInChatMessage.Type]
        UNPIN_FOR_ALL: _ClassVar[PinInChatMessage.Type]
    UNKNOWN_TYPE: PinInChatMessage.Type
    PIN_FOR_ALL: PinInChatMessage.Type
    UNPIN_FOR_ALL: PinInChatMessage.Type
    KEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SENDERTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    type: PinInChatMessage.Type
    senderTimestampMS: int
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., type: _Optional[_Union[PinInChatMessage.Type, str]] = ..., senderTimestampMS: _Optional[int] = ...) -> None: ...

class PollCreationMessage(_message.Message):
    __slots__ = ("encKey", "name", "options", "selectableOptionsCount", "contextInfo", "pollContentType", "pollType", "correctAnswer")
    class PollType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        POLL: _ClassVar[PollCreationMessage.PollType]
        QUIZ: _ClassVar[PollCreationMessage.PollType]
    POLL: PollCreationMessage.PollType
    QUIZ: PollCreationMessage.PollType
    class Option(_message.Message):
        __slots__ = ("optionName", "optionHash")
        OPTIONNAME_FIELD_NUMBER: _ClassVar[int]
        OPTIONHASH_FIELD_NUMBER: _ClassVar[int]
        optionName: str
        optionHash: str
        def __init__(self, optionName: _Optional[str] = ..., optionHash: _Optional[str] = ...) -> None: ...
    ENCKEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OPTIONS_FIELD_NUMBER: _ClassVar[int]
    SELECTABLEOPTIONSCOUNT_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    POLLCONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
    POLLTYPE_FIELD_NUMBER: _ClassVar[int]
    CORRECTANSWER_FIELD_NUMBER: _ClassVar[int]
    encKey: bytes
    name: str
    options: _containers.RepeatedCompositeFieldContainer[PollCreationMessage.Option]
    selectableOptionsCount: int
    contextInfo: ContextInfo
    pollContentType: PollContentType
    pollType: PollCreationMessage.PollType
    correctAnswer: PollCreationMessage.Option
    def __init__(self, encKey: _Optional[bytes] = ..., name: _Optional[str] = ..., options: _Optional[_Iterable[_Union[PollCreationMessage.Option, _Mapping]]] = ..., selectableOptionsCount: _Optional[int] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., pollContentType: _Optional[_Union[PollContentType, str]] = ..., pollType: _Optional[_Union[PollCreationMessage.PollType, str]] = ..., correctAnswer: _Optional[_Union[PollCreationMessage.Option, _Mapping]] = ...) -> None: ...

class ButtonsResponseMessage(_message.Message):
    __slots__ = ("selectedDisplayText", "selectedButtonID", "contextInfo", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ButtonsResponseMessage.Type]
        DISPLAY_TEXT: _ClassVar[ButtonsResponseMessage.Type]
    UNKNOWN: ButtonsResponseMessage.Type
    DISPLAY_TEXT: ButtonsResponseMessage.Type
    SELECTEDDISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
    SELECTEDBUTTONID_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    selectedDisplayText: str
    selectedButtonID: str
    contextInfo: ContextInfo
    type: ButtonsResponseMessage.Type
    def __init__(self, selectedDisplayText: _Optional[str] = ..., selectedButtonID: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., type: _Optional[_Union[ButtonsResponseMessage.Type, str]] = ...) -> None: ...

class ButtonsMessage(_message.Message):
    __slots__ = ("text", "documentMessage", "imageMessage", "videoMessage", "locationMessage", "contentText", "footerText", "contextInfo", "buttons", "headerType")
    class HeaderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ButtonsMessage.HeaderType]
        EMPTY: _ClassVar[ButtonsMessage.HeaderType]
        TEXT: _ClassVar[ButtonsMessage.HeaderType]
        DOCUMENT: _ClassVar[ButtonsMessage.HeaderType]
        IMAGE: _ClassVar[ButtonsMessage.HeaderType]
        VIDEO: _ClassVar[ButtonsMessage.HeaderType]
        LOCATION: _ClassVar[ButtonsMessage.HeaderType]
    UNKNOWN: ButtonsMessage.HeaderType
    EMPTY: ButtonsMessage.HeaderType
    TEXT: ButtonsMessage.HeaderType
    DOCUMENT: ButtonsMessage.HeaderType
    IMAGE: ButtonsMessage.HeaderType
    VIDEO: ButtonsMessage.HeaderType
    LOCATION: ButtonsMessage.HeaderType
    class Button(_message.Message):
        __slots__ = ("buttonID", "buttonText", "type", "nativeFlowInfo")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[ButtonsMessage.Button.Type]
            RESPONSE: _ClassVar[ButtonsMessage.Button.Type]
            NATIVE_FLOW: _ClassVar[ButtonsMessage.Button.Type]
        UNKNOWN: ButtonsMessage.Button.Type
        RESPONSE: ButtonsMessage.Button.Type
        NATIVE_FLOW: ButtonsMessage.Button.Type
        class NativeFlowInfo(_message.Message):
            __slots__ = ("name", "paramsJSON")
            NAME_FIELD_NUMBER: _ClassVar[int]
            PARAMSJSON_FIELD_NUMBER: _ClassVar[int]
            name: str
            paramsJSON: str
            def __init__(self, name: _Optional[str] = ..., paramsJSON: _Optional[str] = ...) -> None: ...
        class ButtonText(_message.Message):
            __slots__ = ("displayText",)
            DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
            displayText: str
            def __init__(self, displayText: _Optional[str] = ...) -> None: ...
        BUTTONID_FIELD_NUMBER: _ClassVar[int]
        BUTTONTEXT_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        NATIVEFLOWINFO_FIELD_NUMBER: _ClassVar[int]
        buttonID: str
        buttonText: ButtonsMessage.Button.ButtonText
        type: ButtonsMessage.Button.Type
        nativeFlowInfo: ButtonsMessage.Button.NativeFlowInfo
        def __init__(self, buttonID: _Optional[str] = ..., buttonText: _Optional[_Union[ButtonsMessage.Button.ButtonText, _Mapping]] = ..., type: _Optional[_Union[ButtonsMessage.Button.Type, str]] = ..., nativeFlowInfo: _Optional[_Union[ButtonsMessage.Button.NativeFlowInfo, _Mapping]] = ...) -> None: ...
    TEXT_FIELD_NUMBER: _ClassVar[int]
    DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTENTTEXT_FIELD_NUMBER: _ClassVar[int]
    FOOTERTEXT_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    BUTTONS_FIELD_NUMBER: _ClassVar[int]
    HEADERTYPE_FIELD_NUMBER: _ClassVar[int]
    text: str
    documentMessage: DocumentMessage
    imageMessage: ImageMessage
    videoMessage: VideoMessage
    locationMessage: LocationMessage
    contentText: str
    footerText: str
    contextInfo: ContextInfo
    buttons: _containers.RepeatedCompositeFieldContainer[ButtonsMessage.Button]
    headerType: ButtonsMessage.HeaderType
    def __init__(self, text: _Optional[str] = ..., documentMessage: _Optional[_Union[DocumentMessage, _Mapping]] = ..., imageMessage: _Optional[_Union[ImageMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[LocationMessage, _Mapping]] = ..., contentText: _Optional[str] = ..., footerText: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., buttons: _Optional[_Iterable[_Union[ButtonsMessage.Button, _Mapping]]] = ..., headerType: _Optional[_Union[ButtonsMessage.HeaderType, str]] = ...) -> None: ...

class SecretEncryptedMessage(_message.Message):
    __slots__ = ("targetMessageKey", "encPayload", "encIV", "secretEncType")
    class SecretEncType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[SecretEncryptedMessage.SecretEncType]
        EVENT_EDIT: _ClassVar[SecretEncryptedMessage.SecretEncType]
        MESSAGE_EDIT: _ClassVar[SecretEncryptedMessage.SecretEncType]
    UNKNOWN: SecretEncryptedMessage.SecretEncType
    EVENT_EDIT: SecretEncryptedMessage.SecretEncType
    MESSAGE_EDIT: SecretEncryptedMessage.SecretEncType
    TARGETMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    SECRETENCTYPE_FIELD_NUMBER: _ClassVar[int]
    targetMessageKey: _WACommon_pb2.MessageKey
    encPayload: bytes
    encIV: bytes
    secretEncType: SecretEncryptedMessage.SecretEncType
    def __init__(self, targetMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ..., secretEncType: _Optional[_Union[SecretEncryptedMessage.SecretEncType, str]] = ...) -> None: ...

class GroupInviteMessage(_message.Message):
    __slots__ = ("groupJID", "inviteCode", "inviteExpiration", "groupName", "JPEGThumbnail", "caption", "contextInfo", "groupType")
    class GroupType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[GroupInviteMessage.GroupType]
        PARENT: _ClassVar[GroupInviteMessage.GroupType]
    DEFAULT: GroupInviteMessage.GroupType
    PARENT: GroupInviteMessage.GroupType
    GROUPJID_FIELD_NUMBER: _ClassVar[int]
    INVITECODE_FIELD_NUMBER: _ClassVar[int]
    INVITEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    GROUPNAME_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    GROUPTYPE_FIELD_NUMBER: _ClassVar[int]
    groupJID: str
    inviteCode: str
    inviteExpiration: int
    groupName: str
    JPEGThumbnail: bytes
    caption: str
    contextInfo: ContextInfo
    groupType: GroupInviteMessage.GroupType
    def __init__(self, groupJID: _Optional[str] = ..., inviteCode: _Optional[str] = ..., inviteExpiration: _Optional[int] = ..., groupName: _Optional[str] = ..., JPEGThumbnail: _Optional[bytes] = ..., caption: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., groupType: _Optional[_Union[GroupInviteMessage.GroupType, str]] = ...) -> None: ...

class InteractiveResponseMessage(_message.Message):
    __slots__ = ("nativeFlowResponseMessage", "body", "contextInfo")
    class Body(_message.Message):
        __slots__ = ("text", "format")
        class Format(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DEFAULT: _ClassVar[InteractiveResponseMessage.Body.Format]
            EXTENSIONS_1: _ClassVar[InteractiveResponseMessage.Body.Format]
        DEFAULT: InteractiveResponseMessage.Body.Format
        EXTENSIONS_1: InteractiveResponseMessage.Body.Format
        TEXT_FIELD_NUMBER: _ClassVar[int]
        FORMAT_FIELD_NUMBER: _ClassVar[int]
        text: str
        format: InteractiveResponseMessage.Body.Format
        def __init__(self, text: _Optional[str] = ..., format: _Optional[_Union[InteractiveResponseMessage.Body.Format, str]] = ...) -> None: ...
    class NativeFlowResponseMessage(_message.Message):
        __slots__ = ("name", "paramsJSON", "version")
        NAME_FIELD_NUMBER: _ClassVar[int]
        PARAMSJSON_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        name: str
        paramsJSON: str
        version: int
        def __init__(self, name: _Optional[str] = ..., paramsJSON: _Optional[str] = ..., version: _Optional[int] = ...) -> None: ...
    NATIVEFLOWRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    nativeFlowResponseMessage: InteractiveResponseMessage.NativeFlowResponseMessage
    body: InteractiveResponseMessage.Body
    contextInfo: ContextInfo
    def __init__(self, nativeFlowResponseMessage: _Optional[_Union[InteractiveResponseMessage.NativeFlowResponseMessage, _Mapping]] = ..., body: _Optional[_Union[InteractiveResponseMessage.Body, _Mapping]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class InteractiveMessage(_message.Message):
    __slots__ = ("shopStorefrontMessage", "collectionMessage", "nativeFlowMessage", "carouselMessage", "header", "body", "footer", "contextInfo", "urlTrackingMap")
    class ShopMessage(_message.Message):
        __slots__ = ("ID", "surface", "messageVersion")
        class Surface(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_SURFACE: _ClassVar[InteractiveMessage.ShopMessage.Surface]
            FB: _ClassVar[InteractiveMessage.ShopMessage.Surface]
            IG: _ClassVar[InteractiveMessage.ShopMessage.Surface]
            WA: _ClassVar[InteractiveMessage.ShopMessage.Surface]
        UNKNOWN_SURFACE: InteractiveMessage.ShopMessage.Surface
        FB: InteractiveMessage.ShopMessage.Surface
        IG: InteractiveMessage.ShopMessage.Surface
        WA: InteractiveMessage.ShopMessage.Surface
        ID_FIELD_NUMBER: _ClassVar[int]
        SURFACE_FIELD_NUMBER: _ClassVar[int]
        MESSAGEVERSION_FIELD_NUMBER: _ClassVar[int]
        ID: str
        surface: InteractiveMessage.ShopMessage.Surface
        messageVersion: int
        def __init__(self, ID: _Optional[str] = ..., surface: _Optional[_Union[InteractiveMessage.ShopMessage.Surface, str]] = ..., messageVersion: _Optional[int] = ...) -> None: ...
    class CarouselMessage(_message.Message):
        __slots__ = ("cards", "messageVersion")
        CARDS_FIELD_NUMBER: _ClassVar[int]
        MESSAGEVERSION_FIELD_NUMBER: _ClassVar[int]
        cards: _containers.RepeatedCompositeFieldContainer[InteractiveMessage]
        messageVersion: int
        def __init__(self, cards: _Optional[_Iterable[_Union[InteractiveMessage, _Mapping]]] = ..., messageVersion: _Optional[int] = ...) -> None: ...
    class NativeFlowMessage(_message.Message):
        __slots__ = ("buttons", "messageParamsJSON", "messageVersion")
        class NativeFlowButton(_message.Message):
            __slots__ = ("name", "buttonParamsJSON")
            NAME_FIELD_NUMBER: _ClassVar[int]
            BUTTONPARAMSJSON_FIELD_NUMBER: _ClassVar[int]
            name: str
            buttonParamsJSON: str
            def __init__(self, name: _Optional[str] = ..., buttonParamsJSON: _Optional[str] = ...) -> None: ...
        BUTTONS_FIELD_NUMBER: _ClassVar[int]
        MESSAGEPARAMSJSON_FIELD_NUMBER: _ClassVar[int]
        MESSAGEVERSION_FIELD_NUMBER: _ClassVar[int]
        buttons: _containers.RepeatedCompositeFieldContainer[InteractiveMessage.NativeFlowMessage.NativeFlowButton]
        messageParamsJSON: str
        messageVersion: int
        def __init__(self, buttons: _Optional[_Iterable[_Union[InteractiveMessage.NativeFlowMessage.NativeFlowButton, _Mapping]]] = ..., messageParamsJSON: _Optional[str] = ..., messageVersion: _Optional[int] = ...) -> None: ...
    class CollectionMessage(_message.Message):
        __slots__ = ("bizJID", "ID", "messageVersion")
        BIZJID_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        MESSAGEVERSION_FIELD_NUMBER: _ClassVar[int]
        bizJID: str
        ID: str
        messageVersion: int
        def __init__(self, bizJID: _Optional[str] = ..., ID: _Optional[str] = ..., messageVersion: _Optional[int] = ...) -> None: ...
    class Footer(_message.Message):
        __slots__ = ("text",)
        TEXT_FIELD_NUMBER: _ClassVar[int]
        text: str
        def __init__(self, text: _Optional[str] = ...) -> None: ...
    class Body(_message.Message):
        __slots__ = ("text",)
        TEXT_FIELD_NUMBER: _ClassVar[int]
        text: str
        def __init__(self, text: _Optional[str] = ...) -> None: ...
    class Header(_message.Message):
        __slots__ = ("documentMessage", "imageMessage", "JPEGThumbnail", "videoMessage", "locationMessage", "productMessage", "title", "subtitle", "hasMediaAttachment")
        DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        PRODUCTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        TITLE_FIELD_NUMBER: _ClassVar[int]
        SUBTITLE_FIELD_NUMBER: _ClassVar[int]
        HASMEDIAATTACHMENT_FIELD_NUMBER: _ClassVar[int]
        documentMessage: DocumentMessage
        imageMessage: ImageMessage
        JPEGThumbnail: bytes
        videoMessage: VideoMessage
        locationMessage: LocationMessage
        productMessage: ProductMessage
        title: str
        subtitle: str
        hasMediaAttachment: bool
        def __init__(self, documentMessage: _Optional[_Union[DocumentMessage, _Mapping]] = ..., imageMessage: _Optional[_Union[ImageMessage, _Mapping]] = ..., JPEGThumbnail: _Optional[bytes] = ..., videoMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[LocationMessage, _Mapping]] = ..., productMessage: _Optional[_Union[ProductMessage, _Mapping]] = ..., title: _Optional[str] = ..., subtitle: _Optional[str] = ..., hasMediaAttachment: bool = ...) -> None: ...
    SHOPSTOREFRONTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    NATIVEFLOWMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CAROUSELMESSAGE_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    FOOTER_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    URLTRACKINGMAP_FIELD_NUMBER: _ClassVar[int]
    shopStorefrontMessage: InteractiveMessage.ShopMessage
    collectionMessage: InteractiveMessage.CollectionMessage
    nativeFlowMessage: InteractiveMessage.NativeFlowMessage
    carouselMessage: InteractiveMessage.CarouselMessage
    header: InteractiveMessage.Header
    body: InteractiveMessage.Body
    footer: InteractiveMessage.Footer
    contextInfo: ContextInfo
    urlTrackingMap: UrlTrackingMap
    def __init__(self, shopStorefrontMessage: _Optional[_Union[InteractiveMessage.ShopMessage, _Mapping]] = ..., collectionMessage: _Optional[_Union[InteractiveMessage.CollectionMessage, _Mapping]] = ..., nativeFlowMessage: _Optional[_Union[InteractiveMessage.NativeFlowMessage, _Mapping]] = ..., carouselMessage: _Optional[_Union[InteractiveMessage.CarouselMessage, _Mapping]] = ..., header: _Optional[_Union[InteractiveMessage.Header, _Mapping]] = ..., body: _Optional[_Union[InteractiveMessage.Body, _Mapping]] = ..., footer: _Optional[_Union[InteractiveMessage.Footer, _Mapping]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., urlTrackingMap: _Optional[_Union[UrlTrackingMap, _Mapping]] = ...) -> None: ...

class ListResponseMessage(_message.Message):
    __slots__ = ("title", "listType", "singleSelectReply", "contextInfo", "description")
    class ListType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ListResponseMessage.ListType]
        SINGLE_SELECT: _ClassVar[ListResponseMessage.ListType]
    UNKNOWN: ListResponseMessage.ListType
    SINGLE_SELECT: ListResponseMessage.ListType
    class SingleSelectReply(_message.Message):
        __slots__ = ("selectedRowID",)
        SELECTEDROWID_FIELD_NUMBER: _ClassVar[int]
        selectedRowID: str
        def __init__(self, selectedRowID: _Optional[str] = ...) -> None: ...
    TITLE_FIELD_NUMBER: _ClassVar[int]
    LISTTYPE_FIELD_NUMBER: _ClassVar[int]
    SINGLESELECTREPLY_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    title: str
    listType: ListResponseMessage.ListType
    singleSelectReply: ListResponseMessage.SingleSelectReply
    contextInfo: ContextInfo
    description: str
    def __init__(self, title: _Optional[str] = ..., listType: _Optional[_Union[ListResponseMessage.ListType, str]] = ..., singleSelectReply: _Optional[_Union[ListResponseMessage.SingleSelectReply, _Mapping]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., description: _Optional[str] = ...) -> None: ...

class ListMessage(_message.Message):
    __slots__ = ("title", "description", "buttonText", "listType", "sections", "productListInfo", "footerText", "contextInfo")
    class ListType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[ListMessage.ListType]
        SINGLE_SELECT: _ClassVar[ListMessage.ListType]
        PRODUCT_LIST: _ClassVar[ListMessage.ListType]
    UNKNOWN: ListMessage.ListType
    SINGLE_SELECT: ListMessage.ListType
    PRODUCT_LIST: ListMessage.ListType
    class ProductListInfo(_message.Message):
        __slots__ = ("productSections", "headerImage", "businessOwnerJID")
        PRODUCTSECTIONS_FIELD_NUMBER: _ClassVar[int]
        HEADERIMAGE_FIELD_NUMBER: _ClassVar[int]
        BUSINESSOWNERJID_FIELD_NUMBER: _ClassVar[int]
        productSections: _containers.RepeatedCompositeFieldContainer[ListMessage.ProductSection]
        headerImage: ListMessage.ProductListHeaderImage
        businessOwnerJID: str
        def __init__(self, productSections: _Optional[_Iterable[_Union[ListMessage.ProductSection, _Mapping]]] = ..., headerImage: _Optional[_Union[ListMessage.ProductListHeaderImage, _Mapping]] = ..., businessOwnerJID: _Optional[str] = ...) -> None: ...
    class ProductListHeaderImage(_message.Message):
        __slots__ = ("productID", "JPEGThumbnail")
        PRODUCTID_FIELD_NUMBER: _ClassVar[int]
        JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        productID: str
        JPEGThumbnail: bytes
        def __init__(self, productID: _Optional[str] = ..., JPEGThumbnail: _Optional[bytes] = ...) -> None: ...
    class ProductSection(_message.Message):
        __slots__ = ("title", "products")
        TITLE_FIELD_NUMBER: _ClassVar[int]
        PRODUCTS_FIELD_NUMBER: _ClassVar[int]
        title: str
        products: _containers.RepeatedCompositeFieldContainer[ListMessage.Product]
        def __init__(self, title: _Optional[str] = ..., products: _Optional[_Iterable[_Union[ListMessage.Product, _Mapping]]] = ...) -> None: ...
    class Product(_message.Message):
        __slots__ = ("productID",)
        PRODUCTID_FIELD_NUMBER: _ClassVar[int]
        productID: str
        def __init__(self, productID: _Optional[str] = ...) -> None: ...
    class Section(_message.Message):
        __slots__ = ("title", "rows")
        TITLE_FIELD_NUMBER: _ClassVar[int]
        ROWS_FIELD_NUMBER: _ClassVar[int]
        title: str
        rows: _containers.RepeatedCompositeFieldContainer[ListMessage.Row]
        def __init__(self, title: _Optional[str] = ..., rows: _Optional[_Iterable[_Union[ListMessage.Row, _Mapping]]] = ...) -> None: ...
    class Row(_message.Message):
        __slots__ = ("title", "description", "rowID")
        TITLE_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        ROWID_FIELD_NUMBER: _ClassVar[int]
        title: str
        description: str
        rowID: str
        def __init__(self, title: _Optional[str] = ..., description: _Optional[str] = ..., rowID: _Optional[str] = ...) -> None: ...
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    BUTTONTEXT_FIELD_NUMBER: _ClassVar[int]
    LISTTYPE_FIELD_NUMBER: _ClassVar[int]
    SECTIONS_FIELD_NUMBER: _ClassVar[int]
    PRODUCTLISTINFO_FIELD_NUMBER: _ClassVar[int]
    FOOTERTEXT_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    title: str
    description: str
    buttonText: str
    listType: ListMessage.ListType
    sections: _containers.RepeatedCompositeFieldContainer[ListMessage.Section]
    productListInfo: ListMessage.ProductListInfo
    footerText: str
    contextInfo: ContextInfo
    def __init__(self, title: _Optional[str] = ..., description: _Optional[str] = ..., buttonText: _Optional[str] = ..., listType: _Optional[_Union[ListMessage.ListType, str]] = ..., sections: _Optional[_Iterable[_Union[ListMessage.Section, _Mapping]]] = ..., productListInfo: _Optional[_Union[ListMessage.ProductListInfo, _Mapping]] = ..., footerText: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class OrderMessage(_message.Message):
    __slots__ = ("orderID", "thumbnail", "itemCount", "status", "surface", "message", "orderTitle", "sellerJID", "token", "totalAmount1000", "totalCurrencyCode", "contextInfo", "messageVersion", "orderRequestMessageID", "catalogType")
    class OrderSurface(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CATALOG: _ClassVar[OrderMessage.OrderSurface]
    CATALOG: OrderMessage.OrderSurface
    class OrderStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        INQUIRY: _ClassVar[OrderMessage.OrderStatus]
        ACCEPTED: _ClassVar[OrderMessage.OrderStatus]
        DECLINED: _ClassVar[OrderMessage.OrderStatus]
    INQUIRY: OrderMessage.OrderStatus
    ACCEPTED: OrderMessage.OrderStatus
    DECLINED: OrderMessage.OrderStatus
    ORDERID_FIELD_NUMBER: _ClassVar[int]
    THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    ITEMCOUNT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SURFACE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ORDERTITLE_FIELD_NUMBER: _ClassVar[int]
    SELLERJID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOTALAMOUNT1000_FIELD_NUMBER: _ClassVar[int]
    TOTALCURRENCYCODE_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    MESSAGEVERSION_FIELD_NUMBER: _ClassVar[int]
    ORDERREQUESTMESSAGEID_FIELD_NUMBER: _ClassVar[int]
    CATALOGTYPE_FIELD_NUMBER: _ClassVar[int]
    orderID: str
    thumbnail: bytes
    itemCount: int
    status: OrderMessage.OrderStatus
    surface: OrderMessage.OrderSurface
    message: str
    orderTitle: str
    sellerJID: str
    token: str
    totalAmount1000: int
    totalCurrencyCode: str
    contextInfo: ContextInfo
    messageVersion: int
    orderRequestMessageID: _WACommon_pb2.MessageKey
    catalogType: str
    def __init__(self, orderID: _Optional[str] = ..., thumbnail: _Optional[bytes] = ..., itemCount: _Optional[int] = ..., status: _Optional[_Union[OrderMessage.OrderStatus, str]] = ..., surface: _Optional[_Union[OrderMessage.OrderSurface, str]] = ..., message: _Optional[str] = ..., orderTitle: _Optional[str] = ..., sellerJID: _Optional[str] = ..., token: _Optional[str] = ..., totalAmount1000: _Optional[int] = ..., totalCurrencyCode: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., messageVersion: _Optional[int] = ..., orderRequestMessageID: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., catalogType: _Optional[str] = ...) -> None: ...

class PaymentInviteMessage(_message.Message):
    __slots__ = ("serviceType", "expiryTimestamp")
    class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[PaymentInviteMessage.ServiceType]
        FBPAY: _ClassVar[PaymentInviteMessage.ServiceType]
        NOVI: _ClassVar[PaymentInviteMessage.ServiceType]
        UPI: _ClassVar[PaymentInviteMessage.ServiceType]
    UNKNOWN: PaymentInviteMessage.ServiceType
    FBPAY: PaymentInviteMessage.ServiceType
    NOVI: PaymentInviteMessage.ServiceType
    UPI: PaymentInviteMessage.ServiceType
    SERVICETYPE_FIELD_NUMBER: _ClassVar[int]
    EXPIRYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    serviceType: PaymentInviteMessage.ServiceType
    expiryTimestamp: int
    def __init__(self, serviceType: _Optional[_Union[PaymentInviteMessage.ServiceType, str]] = ..., expiryTimestamp: _Optional[int] = ...) -> None: ...

class HighlyStructuredMessage(_message.Message):
    __slots__ = ("namespace", "elementName", "params", "fallbackLg", "fallbackLc", "localizableParams", "deterministicLg", "deterministicLc", "hydratedHsm")
    class HSMLocalizableParameter(_message.Message):
        __slots__ = ("currency", "dateTime", "default")
        class HSMDateTime(_message.Message):
            __slots__ = ("component", "unixEpoch")
            class HSMDateTimeComponent(_message.Message):
                __slots__ = ("dayOfWeek", "year", "month", "dayOfMonth", "hour", "minute", "calendar")
                class CalendarType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                    __slots__ = ()
                    GREGORIAN: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType]
                    SOLAR_HIJRI: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType]
                GREGORIAN: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType
                SOLAR_HIJRI: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType
                class DayOfWeekType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                    __slots__ = ()
                    MONDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    TUESDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    WEDNESDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    THURSDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    FRIDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    SATURDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                    SUNDAY: _ClassVar[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType]
                MONDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                TUESDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                WEDNESDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                THURSDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                FRIDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                SATURDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                SUNDAY: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                DAYOFWEEK_FIELD_NUMBER: _ClassVar[int]
                YEAR_FIELD_NUMBER: _ClassVar[int]
                MONTH_FIELD_NUMBER: _ClassVar[int]
                DAYOFMONTH_FIELD_NUMBER: _ClassVar[int]
                HOUR_FIELD_NUMBER: _ClassVar[int]
                MINUTE_FIELD_NUMBER: _ClassVar[int]
                CALENDAR_FIELD_NUMBER: _ClassVar[int]
                dayOfWeek: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType
                year: int
                month: int
                dayOfMonth: int
                hour: int
                minute: int
                calendar: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType
                def __init__(self, dayOfWeek: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.DayOfWeekType, str]] = ..., year: _Optional[int] = ..., month: _Optional[int] = ..., dayOfMonth: _Optional[int] = ..., hour: _Optional[int] = ..., minute: _Optional[int] = ..., calendar: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent.CalendarType, str]] = ...) -> None: ...
            class HSMDateTimeUnixEpoch(_message.Message):
                __slots__ = ("timestamp",)
                TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                timestamp: int
                def __init__(self, timestamp: _Optional[int] = ...) -> None: ...
            COMPONENT_FIELD_NUMBER: _ClassVar[int]
            UNIXEPOCH_FIELD_NUMBER: _ClassVar[int]
            component: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent
            unixEpoch: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeUnixEpoch
            def __init__(self, component: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeComponent, _Mapping]] = ..., unixEpoch: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime.HSMDateTimeUnixEpoch, _Mapping]] = ...) -> None: ...
        class HSMCurrency(_message.Message):
            __slots__ = ("currencyCode", "amount1000")
            CURRENCYCODE_FIELD_NUMBER: _ClassVar[int]
            AMOUNT1000_FIELD_NUMBER: _ClassVar[int]
            currencyCode: str
            amount1000: int
            def __init__(self, currencyCode: _Optional[str] = ..., amount1000: _Optional[int] = ...) -> None: ...
        CURRENCY_FIELD_NUMBER: _ClassVar[int]
        DATETIME_FIELD_NUMBER: _ClassVar[int]
        DEFAULT_FIELD_NUMBER: _ClassVar[int]
        currency: HighlyStructuredMessage.HSMLocalizableParameter.HSMCurrency
        dateTime: HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime
        default: str
        def __init__(self, currency: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMCurrency, _Mapping]] = ..., dateTime: _Optional[_Union[HighlyStructuredMessage.HSMLocalizableParameter.HSMDateTime, _Mapping]] = ..., default: _Optional[str] = ...) -> None: ...
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    ELEMENTNAME_FIELD_NUMBER: _ClassVar[int]
    PARAMS_FIELD_NUMBER: _ClassVar[int]
    FALLBACKLG_FIELD_NUMBER: _ClassVar[int]
    FALLBACKLC_FIELD_NUMBER: _ClassVar[int]
    LOCALIZABLEPARAMS_FIELD_NUMBER: _ClassVar[int]
    DETERMINISTICLG_FIELD_NUMBER: _ClassVar[int]
    DETERMINISTICLC_FIELD_NUMBER: _ClassVar[int]
    HYDRATEDHSM_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    elementName: str
    params: _containers.RepeatedScalarFieldContainer[str]
    fallbackLg: str
    fallbackLc: str
    localizableParams: _containers.RepeatedCompositeFieldContainer[HighlyStructuredMessage.HSMLocalizableParameter]
    deterministicLg: str
    deterministicLc: str
    hydratedHsm: TemplateMessage
    def __init__(self, namespace: _Optional[str] = ..., elementName: _Optional[str] = ..., params: _Optional[_Iterable[str]] = ..., fallbackLg: _Optional[str] = ..., fallbackLc: _Optional[str] = ..., localizableParams: _Optional[_Iterable[_Union[HighlyStructuredMessage.HSMLocalizableParameter, _Mapping]]] = ..., deterministicLg: _Optional[str] = ..., deterministicLc: _Optional[str] = ..., hydratedHsm: _Optional[_Union[TemplateMessage, _Mapping]] = ...) -> None: ...

class PeerDataOperationRequestResponseMessage(_message.Message):
    __slots__ = ("peerDataOperationRequestType", "stanzaID", "peerDataOperationResult")
    class PeerDataOperationResult(_message.Message):
        __slots__ = ("mediaUploadResult", "stickerMessage", "linkPreviewResponse", "placeholderMessageResendResponse", "waffleNonceFetchRequestResponse", "fullHistorySyncOnDemandRequestResponse", "companionMetaNonceFetchRequestResponse", "syncdSnapshotFatalRecoveryResponse")
        class FullHistorySyncOnDemandResponseCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            REQUEST_SUCCESS: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            REQUEST_TIME_EXPIRED: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            DECLINED_SHARING_HISTORY: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            GENERIC_ERROR: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            ERROR_REQUEST_ON_NON_SMB_PRIMARY: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            ERROR_HOSTED_DEVICE_NOT_CONNECTED: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
            ERROR_HOSTED_DEVICE_LOGIN_TIME_NOT_SET: _ClassVar[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode]
        REQUEST_SUCCESS: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        REQUEST_TIME_EXPIRED: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        DECLINED_SHARING_HISTORY: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        GENERIC_ERROR: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        ERROR_REQUEST_ON_NON_SMB_PRIMARY: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        ERROR_HOSTED_DEVICE_NOT_CONNECTED: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        ERROR_HOSTED_DEVICE_LOGIN_TIME_NOT_SET: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
        class SyncDSnapshotFatalRecoveryResponse(_message.Message):
            __slots__ = ("collectionSnapshot", "isCompressed")
            COLLECTIONSNAPSHOT_FIELD_NUMBER: _ClassVar[int]
            ISCOMPRESSED_FIELD_NUMBER: _ClassVar[int]
            collectionSnapshot: bytes
            isCompressed: bool
            def __init__(self, collectionSnapshot: _Optional[bytes] = ..., isCompressed: bool = ...) -> None: ...
        class CompanionMetaNonceFetchResponse(_message.Message):
            __slots__ = ("nonce",)
            NONCE_FIELD_NUMBER: _ClassVar[int]
            nonce: str
            def __init__(self, nonce: _Optional[str] = ...) -> None: ...
        class WaffleNonceFetchResponse(_message.Message):
            __slots__ = ("nonce", "waEntFbid")
            NONCE_FIELD_NUMBER: _ClassVar[int]
            WAENTFBID_FIELD_NUMBER: _ClassVar[int]
            nonce: str
            waEntFbid: str
            def __init__(self, nonce: _Optional[str] = ..., waEntFbid: _Optional[str] = ...) -> None: ...
        class FullHistorySyncOnDemandRequestResponse(_message.Message):
            __slots__ = ("requestMetadata", "responseCode")
            REQUESTMETADATA_FIELD_NUMBER: _ClassVar[int]
            RESPONSECODE_FIELD_NUMBER: _ClassVar[int]
            requestMetadata: FullHistorySyncOnDemandRequestMetadata
            responseCode: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode
            def __init__(self, requestMetadata: _Optional[_Union[FullHistorySyncOnDemandRequestMetadata, _Mapping]] = ..., responseCode: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandResponseCode, str]] = ...) -> None: ...
        class PlaceholderMessageResendResponse(_message.Message):
            __slots__ = ("webMessageInfoBytes",)
            WEBMESSAGEINFOBYTES_FIELD_NUMBER: _ClassVar[int]
            webMessageInfoBytes: bytes
            def __init__(self, webMessageInfoBytes: _Optional[bytes] = ...) -> None: ...
        class LinkPreviewResponse(_message.Message):
            __slots__ = ("URL", "title", "description", "thumbData", "matchText", "previewType", "hqThumbnail")
            class LinkPreviewHighQualityThumbnail(_message.Message):
                __slots__ = ("directPath", "thumbHash", "encThumbHash", "mediaKey", "mediaKeyTimestampMS", "thumbWidth", "thumbHeight")
                DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
                THUMBHASH_FIELD_NUMBER: _ClassVar[int]
                ENCTHUMBHASH_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEYTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
                THUMBWIDTH_FIELD_NUMBER: _ClassVar[int]
                THUMBHEIGHT_FIELD_NUMBER: _ClassVar[int]
                directPath: str
                thumbHash: str
                encThumbHash: str
                mediaKey: bytes
                mediaKeyTimestampMS: int
                thumbWidth: int
                thumbHeight: int
                def __init__(self, directPath: _Optional[str] = ..., thumbHash: _Optional[str] = ..., encThumbHash: _Optional[str] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestampMS: _Optional[int] = ..., thumbWidth: _Optional[int] = ..., thumbHeight: _Optional[int] = ...) -> None: ...
            URL_FIELD_NUMBER: _ClassVar[int]
            TITLE_FIELD_NUMBER: _ClassVar[int]
            DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
            THUMBDATA_FIELD_NUMBER: _ClassVar[int]
            MATCHTEXT_FIELD_NUMBER: _ClassVar[int]
            PREVIEWTYPE_FIELD_NUMBER: _ClassVar[int]
            HQTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
            URL: str
            title: str
            description: str
            thumbData: bytes
            matchText: str
            previewType: str
            hqThumbnail: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.LinkPreviewResponse.LinkPreviewHighQualityThumbnail
            def __init__(self, URL: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., thumbData: _Optional[bytes] = ..., matchText: _Optional[str] = ..., previewType: _Optional[str] = ..., hqThumbnail: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.LinkPreviewResponse.LinkPreviewHighQualityThumbnail, _Mapping]] = ...) -> None: ...
        MEDIAUPLOADRESULT_FIELD_NUMBER: _ClassVar[int]
        STICKERMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LINKPREVIEWRESPONSE_FIELD_NUMBER: _ClassVar[int]
        PLACEHOLDERMESSAGERESENDRESPONSE_FIELD_NUMBER: _ClassVar[int]
        WAFFLENONCEFETCHREQUESTRESPONSE_FIELD_NUMBER: _ClassVar[int]
        FULLHISTORYSYNCONDEMANDREQUESTRESPONSE_FIELD_NUMBER: _ClassVar[int]
        COMPANIONMETANONCEFETCHREQUESTRESPONSE_FIELD_NUMBER: _ClassVar[int]
        SYNCDSNAPSHOTFATALRECOVERYRESPONSE_FIELD_NUMBER: _ClassVar[int]
        mediaUploadResult: _WAMmsRetry_pb2.MediaRetryNotification.ResultType
        stickerMessage: StickerMessage
        linkPreviewResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.LinkPreviewResponse
        placeholderMessageResendResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.PlaceholderMessageResendResponse
        waffleNonceFetchRequestResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.WaffleNonceFetchResponse
        fullHistorySyncOnDemandRequestResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandRequestResponse
        companionMetaNonceFetchRequestResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.CompanionMetaNonceFetchResponse
        syncdSnapshotFatalRecoveryResponse: PeerDataOperationRequestResponseMessage.PeerDataOperationResult.SyncDSnapshotFatalRecoveryResponse
        def __init__(self, mediaUploadResult: _Optional[_Union[_WAMmsRetry_pb2.MediaRetryNotification.ResultType, str]] = ..., stickerMessage: _Optional[_Union[StickerMessage, _Mapping]] = ..., linkPreviewResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.LinkPreviewResponse, _Mapping]] = ..., placeholderMessageResendResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.PlaceholderMessageResendResponse, _Mapping]] = ..., waffleNonceFetchRequestResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.WaffleNonceFetchResponse, _Mapping]] = ..., fullHistorySyncOnDemandRequestResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.FullHistorySyncOnDemandRequestResponse, _Mapping]] = ..., companionMetaNonceFetchRequestResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.CompanionMetaNonceFetchResponse, _Mapping]] = ..., syncdSnapshotFatalRecoveryResponse: _Optional[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult.SyncDSnapshotFatalRecoveryResponse, _Mapping]] = ...) -> None: ...
    PEERDATAOPERATIONREQUESTTYPE_FIELD_NUMBER: _ClassVar[int]
    STANZAID_FIELD_NUMBER: _ClassVar[int]
    PEERDATAOPERATIONRESULT_FIELD_NUMBER: _ClassVar[int]
    peerDataOperationRequestType: PeerDataOperationRequestType
    stanzaID: str
    peerDataOperationResult: _containers.RepeatedCompositeFieldContainer[PeerDataOperationRequestResponseMessage.PeerDataOperationResult]
    def __init__(self, peerDataOperationRequestType: _Optional[_Union[PeerDataOperationRequestType, str]] = ..., stanzaID: _Optional[str] = ..., peerDataOperationResult: _Optional[_Iterable[_Union[PeerDataOperationRequestResponseMessage.PeerDataOperationResult, _Mapping]]] = ...) -> None: ...

class HistorySyncNotification(_message.Message):
    __slots__ = ("fileSHA256", "fileLength", "mediaKey", "fileEncSHA256", "directPath", "syncType", "chunkOrder", "originalMessageID", "progress", "oldestMsgInChunkTimestampSec", "initialHistBootstrapInlinePayload", "peerDataRequestSessionID", "fullHistorySyncOnDemandRequestMetadata", "encHandle")
    class HistorySyncType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        INITIAL_BOOTSTRAP: _ClassVar[HistorySyncNotification.HistorySyncType]
        INITIAL_STATUS_V3: _ClassVar[HistorySyncNotification.HistorySyncType]
        FULL: _ClassVar[HistorySyncNotification.HistorySyncType]
        RECENT: _ClassVar[HistorySyncNotification.HistorySyncType]
        PUSH_NAME: _ClassVar[HistorySyncNotification.HistorySyncType]
        NON_BLOCKING_DATA: _ClassVar[HistorySyncNotification.HistorySyncType]
        ON_DEMAND: _ClassVar[HistorySyncNotification.HistorySyncType]
        NO_HISTORY: _ClassVar[HistorySyncNotification.HistorySyncType]
    INITIAL_BOOTSTRAP: HistorySyncNotification.HistorySyncType
    INITIAL_STATUS_V3: HistorySyncNotification.HistorySyncType
    FULL: HistorySyncNotification.HistorySyncType
    RECENT: HistorySyncNotification.HistorySyncType
    PUSH_NAME: HistorySyncNotification.HistorySyncType
    NON_BLOCKING_DATA: HistorySyncNotification.HistorySyncType
    ON_DEMAND: HistorySyncNotification.HistorySyncType
    NO_HISTORY: HistorySyncNotification.HistorySyncType
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    SYNCTYPE_FIELD_NUMBER: _ClassVar[int]
    CHUNKORDER_FIELD_NUMBER: _ClassVar[int]
    ORIGINALMESSAGEID_FIELD_NUMBER: _ClassVar[int]
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    OLDESTMSGINCHUNKTIMESTAMPSEC_FIELD_NUMBER: _ClassVar[int]
    INITIALHISTBOOTSTRAPINLINEPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    PEERDATAREQUESTSESSIONID_FIELD_NUMBER: _ClassVar[int]
    FULLHISTORYSYNCONDEMANDREQUESTMETADATA_FIELD_NUMBER: _ClassVar[int]
    ENCHANDLE_FIELD_NUMBER: _ClassVar[int]
    fileSHA256: bytes
    fileLength: int
    mediaKey: bytes
    fileEncSHA256: bytes
    directPath: str
    syncType: HistorySyncNotification.HistorySyncType
    chunkOrder: int
    originalMessageID: str
    progress: int
    oldestMsgInChunkTimestampSec: int
    initialHistBootstrapInlinePayload: bytes
    peerDataRequestSessionID: str
    fullHistorySyncOnDemandRequestMetadata: FullHistorySyncOnDemandRequestMetadata
    encHandle: str
    def __init__(self, fileSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., syncType: _Optional[_Union[HistorySyncNotification.HistorySyncType, str]] = ..., chunkOrder: _Optional[int] = ..., originalMessageID: _Optional[str] = ..., progress: _Optional[int] = ..., oldestMsgInChunkTimestampSec: _Optional[int] = ..., initialHistBootstrapInlinePayload: _Optional[bytes] = ..., peerDataRequestSessionID: _Optional[str] = ..., fullHistorySyncOnDemandRequestMetadata: _Optional[_Union[FullHistorySyncOnDemandRequestMetadata, _Mapping]] = ..., encHandle: _Optional[str] = ...) -> None: ...

class RequestWelcomeMessageMetadata(_message.Message):
    __slots__ = ("localChatState",)
    class LocalChatState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        EMPTY: _ClassVar[RequestWelcomeMessageMetadata.LocalChatState]
        NON_EMPTY: _ClassVar[RequestWelcomeMessageMetadata.LocalChatState]
    EMPTY: RequestWelcomeMessageMetadata.LocalChatState
    NON_EMPTY: RequestWelcomeMessageMetadata.LocalChatState
    LOCALCHATSTATE_FIELD_NUMBER: _ClassVar[int]
    localChatState: RequestWelcomeMessageMetadata.LocalChatState
    def __init__(self, localChatState: _Optional[_Union[RequestWelcomeMessageMetadata.LocalChatState, str]] = ...) -> None: ...

class ProtocolMessage(_message.Message):
    __slots__ = ("key", "type", "ephemeralExpiration", "ephemeralSettingTimestamp", "historySyncNotification", "appStateSyncKeyShare", "appStateSyncKeyRequest", "initialSecurityNotificationSettingSync", "appStateFatalExceptionNotification", "disappearingMode", "editedMessage", "timestampMS", "peerDataOperationRequestMessage", "peerDataOperationRequestResponseMessage", "botFeedbackMessage", "invokerJID", "requestWelcomeMessageMetadata", "mediaNotifyMessage", "cloudApiThreadControlNotification", "lidMigrationMappingSyncMessage", "limitSharing", "aiPsiMetadata", "aiQueryFanout", "memberLabel")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REVOKE: _ClassVar[ProtocolMessage.Type]
        EPHEMERAL_SETTING: _ClassVar[ProtocolMessage.Type]
        EPHEMERAL_SYNC_RESPONSE: _ClassVar[ProtocolMessage.Type]
        HISTORY_SYNC_NOTIFICATION: _ClassVar[ProtocolMessage.Type]
        APP_STATE_SYNC_KEY_SHARE: _ClassVar[ProtocolMessage.Type]
        APP_STATE_SYNC_KEY_REQUEST: _ClassVar[ProtocolMessage.Type]
        MSG_FANOUT_BACKFILL_REQUEST: _ClassVar[ProtocolMessage.Type]
        INITIAL_SECURITY_NOTIFICATION_SETTING_SYNC: _ClassVar[ProtocolMessage.Type]
        APP_STATE_FATAL_EXCEPTION_NOTIFICATION: _ClassVar[ProtocolMessage.Type]
        SHARE_PHONE_NUMBER: _ClassVar[ProtocolMessage.Type]
        MESSAGE_EDIT: _ClassVar[ProtocolMessage.Type]
        PEER_DATA_OPERATION_REQUEST_MESSAGE: _ClassVar[ProtocolMessage.Type]
        PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE: _ClassVar[ProtocolMessage.Type]
        REQUEST_WELCOME_MESSAGE: _ClassVar[ProtocolMessage.Type]
        BOT_FEEDBACK_MESSAGE: _ClassVar[ProtocolMessage.Type]
        MEDIA_NOTIFY_MESSAGE: _ClassVar[ProtocolMessage.Type]
        CLOUD_API_THREAD_CONTROL_NOTIFICATION: _ClassVar[ProtocolMessage.Type]
        LID_MIGRATION_MAPPING_SYNC: _ClassVar[ProtocolMessage.Type]
        REMINDER_MESSAGE: _ClassVar[ProtocolMessage.Type]
        BOT_MEMU_ONBOARDING_MESSAGE: _ClassVar[ProtocolMessage.Type]
        STATUS_MENTION_MESSAGE: _ClassVar[ProtocolMessage.Type]
        STOP_GENERATION_MESSAGE: _ClassVar[ProtocolMessage.Type]
        LIMIT_SHARING: _ClassVar[ProtocolMessage.Type]
        AI_PSI_METADATA: _ClassVar[ProtocolMessage.Type]
        AI_QUERY_FANOUT: _ClassVar[ProtocolMessage.Type]
        GROUP_MEMBER_LABEL_CHANGE: _ClassVar[ProtocolMessage.Type]
    REVOKE: ProtocolMessage.Type
    EPHEMERAL_SETTING: ProtocolMessage.Type
    EPHEMERAL_SYNC_RESPONSE: ProtocolMessage.Type
    HISTORY_SYNC_NOTIFICATION: ProtocolMessage.Type
    APP_STATE_SYNC_KEY_SHARE: ProtocolMessage.Type
    APP_STATE_SYNC_KEY_REQUEST: ProtocolMessage.Type
    MSG_FANOUT_BACKFILL_REQUEST: ProtocolMessage.Type
    INITIAL_SECURITY_NOTIFICATION_SETTING_SYNC: ProtocolMessage.Type
    APP_STATE_FATAL_EXCEPTION_NOTIFICATION: ProtocolMessage.Type
    SHARE_PHONE_NUMBER: ProtocolMessage.Type
    MESSAGE_EDIT: ProtocolMessage.Type
    PEER_DATA_OPERATION_REQUEST_MESSAGE: ProtocolMessage.Type
    PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE: ProtocolMessage.Type
    REQUEST_WELCOME_MESSAGE: ProtocolMessage.Type
    BOT_FEEDBACK_MESSAGE: ProtocolMessage.Type
    MEDIA_NOTIFY_MESSAGE: ProtocolMessage.Type
    CLOUD_API_THREAD_CONTROL_NOTIFICATION: ProtocolMessage.Type
    LID_MIGRATION_MAPPING_SYNC: ProtocolMessage.Type
    REMINDER_MESSAGE: ProtocolMessage.Type
    BOT_MEMU_ONBOARDING_MESSAGE: ProtocolMessage.Type
    STATUS_MENTION_MESSAGE: ProtocolMessage.Type
    STOP_GENERATION_MESSAGE: ProtocolMessage.Type
    LIMIT_SHARING: ProtocolMessage.Type
    AI_PSI_METADATA: ProtocolMessage.Type
    AI_QUERY_FANOUT: ProtocolMessage.Type
    GROUP_MEMBER_LABEL_CHANGE: ProtocolMessage.Type
    KEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    HISTORYSYNCNOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    APPSTATESYNCKEYSHARE_FIELD_NUMBER: _ClassVar[int]
    APPSTATESYNCKEYREQUEST_FIELD_NUMBER: _ClassVar[int]
    INITIALSECURITYNOTIFICATIONSETTINGSYNC_FIELD_NUMBER: _ClassVar[int]
    APPSTATEFATALEXCEPTIONNOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMODE_FIELD_NUMBER: _ClassVar[int]
    EDITEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    PEERDATAOPERATIONREQUESTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PEERDATAOPERATIONREQUESTRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BOTFEEDBACKMESSAGE_FIELD_NUMBER: _ClassVar[int]
    INVOKERJID_FIELD_NUMBER: _ClassVar[int]
    REQUESTWELCOMEMESSAGEMETADATA_FIELD_NUMBER: _ClassVar[int]
    MEDIANOTIFYMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CLOUDAPITHREADCONTROLNOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    LIDMIGRATIONMAPPINGSYNCMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARING_FIELD_NUMBER: _ClassVar[int]
    AIPSIMETADATA_FIELD_NUMBER: _ClassVar[int]
    AIQUERYFANOUT_FIELD_NUMBER: _ClassVar[int]
    MEMBERLABEL_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    type: ProtocolMessage.Type
    ephemeralExpiration: int
    ephemeralSettingTimestamp: int
    historySyncNotification: HistorySyncNotification
    appStateSyncKeyShare: AppStateSyncKeyShare
    appStateSyncKeyRequest: AppStateSyncKeyRequest
    initialSecurityNotificationSettingSync: InitialSecurityNotificationSettingSync
    appStateFatalExceptionNotification: AppStateFatalExceptionNotification
    disappearingMode: DisappearingMode
    editedMessage: Message
    timestampMS: int
    peerDataOperationRequestMessage: PeerDataOperationRequestMessage
    peerDataOperationRequestResponseMessage: PeerDataOperationRequestResponseMessage
    botFeedbackMessage: BotFeedbackMessage
    invokerJID: str
    requestWelcomeMessageMetadata: RequestWelcomeMessageMetadata
    mediaNotifyMessage: MediaNotifyMessage
    cloudApiThreadControlNotification: CloudAPIThreadControlNotification
    lidMigrationMappingSyncMessage: LIDMigrationMappingSyncMessage
    limitSharing: _WACommon_pb2.LimitSharing
    aiPsiMetadata: bytes
    aiQueryFanout: AIQueryFanout
    memberLabel: MemberLabel
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., type: _Optional[_Union[ProtocolMessage.Type, str]] = ..., ephemeralExpiration: _Optional[int] = ..., ephemeralSettingTimestamp: _Optional[int] = ..., historySyncNotification: _Optional[_Union[HistorySyncNotification, _Mapping]] = ..., appStateSyncKeyShare: _Optional[_Union[AppStateSyncKeyShare, _Mapping]] = ..., appStateSyncKeyRequest: _Optional[_Union[AppStateSyncKeyRequest, _Mapping]] = ..., initialSecurityNotificationSettingSync: _Optional[_Union[InitialSecurityNotificationSettingSync, _Mapping]] = ..., appStateFatalExceptionNotification: _Optional[_Union[AppStateFatalExceptionNotification, _Mapping]] = ..., disappearingMode: _Optional[_Union[DisappearingMode, _Mapping]] = ..., editedMessage: _Optional[_Union[Message, _Mapping]] = ..., timestampMS: _Optional[int] = ..., peerDataOperationRequestMessage: _Optional[_Union[PeerDataOperationRequestMessage, _Mapping]] = ..., peerDataOperationRequestResponseMessage: _Optional[_Union[PeerDataOperationRequestResponseMessage, _Mapping]] = ..., botFeedbackMessage: _Optional[_Union[BotFeedbackMessage, _Mapping]] = ..., invokerJID: _Optional[str] = ..., requestWelcomeMessageMetadata: _Optional[_Union[RequestWelcomeMessageMetadata, _Mapping]] = ..., mediaNotifyMessage: _Optional[_Union[MediaNotifyMessage, _Mapping]] = ..., cloudApiThreadControlNotification: _Optional[_Union[CloudAPIThreadControlNotification, _Mapping]] = ..., lidMigrationMappingSyncMessage: _Optional[_Union[LIDMigrationMappingSyncMessage, _Mapping]] = ..., limitSharing: _Optional[_Union[_WACommon_pb2.LimitSharing, _Mapping]] = ..., aiPsiMetadata: _Optional[bytes] = ..., aiQueryFanout: _Optional[_Union[AIQueryFanout, _Mapping]] = ..., memberLabel: _Optional[_Union[MemberLabel, _Mapping]] = ...) -> None: ...

class CloudAPIThreadControlNotification(_message.Message):
    __slots__ = ("status", "senderNotificationTimestampMS", "consumerLid", "consumerPhoneNumber", "notificationContent")
    class CloudAPIThreadControl(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[CloudAPIThreadControlNotification.CloudAPIThreadControl]
        CONTROL_PASSED: _ClassVar[CloudAPIThreadControlNotification.CloudAPIThreadControl]
        CONTROL_TAKEN: _ClassVar[CloudAPIThreadControlNotification.CloudAPIThreadControl]
    UNKNOWN: CloudAPIThreadControlNotification.CloudAPIThreadControl
    CONTROL_PASSED: CloudAPIThreadControlNotification.CloudAPIThreadControl
    CONTROL_TAKEN: CloudAPIThreadControlNotification.CloudAPIThreadControl
    class CloudAPIThreadControlNotificationContent(_message.Message):
        __slots__ = ("handoffNotificationText", "extraJSON")
        HANDOFFNOTIFICATIONTEXT_FIELD_NUMBER: _ClassVar[int]
        EXTRAJSON_FIELD_NUMBER: _ClassVar[int]
        handoffNotificationText: str
        extraJSON: str
        def __init__(self, handoffNotificationText: _Optional[str] = ..., extraJSON: _Optional[str] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SENDERNOTIFICATIONTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    CONSUMERLID_FIELD_NUMBER: _ClassVar[int]
    CONSUMERPHONENUMBER_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATIONCONTENT_FIELD_NUMBER: _ClassVar[int]
    status: CloudAPIThreadControlNotification.CloudAPIThreadControl
    senderNotificationTimestampMS: int
    consumerLid: str
    consumerPhoneNumber: str
    notificationContent: CloudAPIThreadControlNotification.CloudAPIThreadControlNotificationContent
    def __init__(self, status: _Optional[_Union[CloudAPIThreadControlNotification.CloudAPIThreadControl, str]] = ..., senderNotificationTimestampMS: _Optional[int] = ..., consumerLid: _Optional[str] = ..., consumerPhoneNumber: _Optional[str] = ..., notificationContent: _Optional[_Union[CloudAPIThreadControlNotification.CloudAPIThreadControlNotificationContent, _Mapping]] = ...) -> None: ...

class BotFeedbackMessage(_message.Message):
    __slots__ = ("messageKey", "kind", "text", "kindNegative", "kindPositive", "kindReport")
    class ReportKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        GENERIC: _ClassVar[BotFeedbackMessage.ReportKind]
    GENERIC: BotFeedbackMessage.ReportKind
    class BotFeedbackKindMultiplePositive(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BOT_FEEDBACK_MULTIPLE_POSITIVE_GENERIC: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultiplePositive]
    BOT_FEEDBACK_MULTIPLE_POSITIVE_GENERIC: BotFeedbackMessage.BotFeedbackKindMultiplePositive
    class BotFeedbackKindMultipleNegative(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_GENERIC: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_HELPFUL: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_INTERESTING: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_ACCURATE: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_SAFE: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_OTHER: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_REFUSED: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_NOT_VISUALLY_APPEALING: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
        BOT_FEEDBACK_MULTIPLE_NEGATIVE_NOT_RELEVANT_TO_TEXT: _ClassVar[BotFeedbackMessage.BotFeedbackKindMultipleNegative]
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_GENERIC: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_HELPFUL: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_INTERESTING: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_ACCURATE: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_SAFE: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_OTHER: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_REFUSED: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_NOT_VISUALLY_APPEALING: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    BOT_FEEDBACK_MULTIPLE_NEGATIVE_NOT_RELEVANT_TO_TEXT: BotFeedbackMessage.BotFeedbackKindMultipleNegative
    class BotFeedbackKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BOT_FEEDBACK_POSITIVE: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_GENERIC: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_HELPFUL: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_INTERESTING: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_ACCURATE: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_SAFE: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_OTHER: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_REFUSED: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_NOT_VISUALLY_APPEALING: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_NOT_RELEVANT_TO_TEXT: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_PERSONALIZED: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_CLARITY: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
        BOT_FEEDBACK_NEGATIVE_DOESNT_LOOK_LIKE_THE_PERSON: _ClassVar[BotFeedbackMessage.BotFeedbackKind]
    BOT_FEEDBACK_POSITIVE: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_GENERIC: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_HELPFUL: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_INTERESTING: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_ACCURATE: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_SAFE: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_OTHER: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_REFUSED: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_NOT_VISUALLY_APPEALING: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_NOT_RELEVANT_TO_TEXT: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_PERSONALIZED: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_CLARITY: BotFeedbackMessage.BotFeedbackKind
    BOT_FEEDBACK_NEGATIVE_DOESNT_LOOK_LIKE_THE_PERSON: BotFeedbackMessage.BotFeedbackKind
    MESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    KINDNEGATIVE_FIELD_NUMBER: _ClassVar[int]
    KINDPOSITIVE_FIELD_NUMBER: _ClassVar[int]
    KINDREPORT_FIELD_NUMBER: _ClassVar[int]
    messageKey: _WACommon_pb2.MessageKey
    kind: BotFeedbackMessage.BotFeedbackKind
    text: str
    kindNegative: int
    kindPositive: int
    kindReport: BotFeedbackMessage.ReportKind
    def __init__(self, messageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., kind: _Optional[_Union[BotFeedbackMessage.BotFeedbackKind, str]] = ..., text: _Optional[str] = ..., kindNegative: _Optional[int] = ..., kindPositive: _Optional[int] = ..., kindReport: _Optional[_Union[BotFeedbackMessage.ReportKind, str]] = ...) -> None: ...

class VideoMessage(_message.Message):
    __slots__ = ("URL", "mimetype", "fileSHA256", "fileLength", "seconds", "mediaKey", "caption", "gifPlayback", "height", "width", "fileEncSHA256", "interactiveAnnotations", "directPath", "mediaKeyTimestamp", "JPEGThumbnail", "contextInfo", "streamingSidecar", "gifAttribution", "viewOnce", "thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "staticURL", "annotations", "accessibilityLabel", "processedVideos", "externalShareFullVideoDurationInSeconds")
    class Attribution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[VideoMessage.Attribution]
        GIPHY: _ClassVar[VideoMessage.Attribution]
        TENOR: _ClassVar[VideoMessage.Attribution]
    NONE: VideoMessage.Attribution
    GIPHY: VideoMessage.Attribution
    TENOR: VideoMessage.Attribution
    URL_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    GIFPLAYBACK_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVEANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    STREAMINGSIDECAR_FIELD_NUMBER: _ClassVar[int]
    GIFATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
    VIEWONCE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    STATICURL_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
    PROCESSEDVIDEOS_FIELD_NUMBER: _ClassVar[int]
    EXTERNALSHAREFULLVIDEODURATIONINSECONDS_FIELD_NUMBER: _ClassVar[int]
    URL: str
    mimetype: str
    fileSHA256: bytes
    fileLength: int
    seconds: int
    mediaKey: bytes
    caption: str
    gifPlayback: bool
    height: int
    width: int
    fileEncSHA256: bytes
    interactiveAnnotations: _containers.RepeatedCompositeFieldContainer[InteractiveAnnotation]
    directPath: str
    mediaKeyTimestamp: int
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    streamingSidecar: bytes
    gifAttribution: VideoMessage.Attribution
    viewOnce: bool
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    staticURL: str
    annotations: _containers.RepeatedCompositeFieldContainer[InteractiveAnnotation]
    accessibilityLabel: str
    processedVideos: _containers.RepeatedCompositeFieldContainer[ProcessedVideo]
    externalShareFullVideoDurationInSeconds: int
    def __init__(self, URL: _Optional[str] = ..., mimetype: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ..., seconds: _Optional[int] = ..., mediaKey: _Optional[bytes] = ..., caption: _Optional[str] = ..., gifPlayback: bool = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., fileEncSHA256: _Optional[bytes] = ..., interactiveAnnotations: _Optional[_Iterable[_Union[InteractiveAnnotation, _Mapping]]] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., streamingSidecar: _Optional[bytes] = ..., gifAttribution: _Optional[_Union[VideoMessage.Attribution, str]] = ..., viewOnce: bool = ..., thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., staticURL: _Optional[str] = ..., annotations: _Optional[_Iterable[_Union[InteractiveAnnotation, _Mapping]]] = ..., accessibilityLabel: _Optional[str] = ..., processedVideos: _Optional[_Iterable[_Union[ProcessedVideo, _Mapping]]] = ..., externalShareFullVideoDurationInSeconds: _Optional[int] = ...) -> None: ...

class ExtendedTextMessage(_message.Message):
    __slots__ = ("text", "matchedText", "description", "title", "textArgb", "backgroundArgb", "font", "previewType", "JPEGThumbnail", "contextInfo", "doNotPlayInline", "thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "mediaKey", "mediaKeyTimestamp", "thumbnailHeight", "thumbnailWidth", "inviteLinkGroupType", "inviteLinkParentGroupSubjectV2", "inviteLinkParentGroupThumbnailV2", "inviteLinkGroupTypeV2", "viewOnce", "videoHeight", "videoWidth", "faviconMMSMetadata", "linkPreviewMetadata", "paymentLinkMetadata")
    class InviteLinkGroupType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[ExtendedTextMessage.InviteLinkGroupType]
        PARENT: _ClassVar[ExtendedTextMessage.InviteLinkGroupType]
        SUB: _ClassVar[ExtendedTextMessage.InviteLinkGroupType]
        DEFAULT_SUB: _ClassVar[ExtendedTextMessage.InviteLinkGroupType]
    DEFAULT: ExtendedTextMessage.InviteLinkGroupType
    PARENT: ExtendedTextMessage.InviteLinkGroupType
    SUB: ExtendedTextMessage.InviteLinkGroupType
    DEFAULT_SUB: ExtendedTextMessage.InviteLinkGroupType
    class PreviewType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[ExtendedTextMessage.PreviewType]
        VIDEO: _ClassVar[ExtendedTextMessage.PreviewType]
        PLACEHOLDER: _ClassVar[ExtendedTextMessage.PreviewType]
        IMAGE: _ClassVar[ExtendedTextMessage.PreviewType]
        PAYMENT_LINKS: _ClassVar[ExtendedTextMessage.PreviewType]
        PROFILE: _ClassVar[ExtendedTextMessage.PreviewType]
    NONE: ExtendedTextMessage.PreviewType
    VIDEO: ExtendedTextMessage.PreviewType
    PLACEHOLDER: ExtendedTextMessage.PreviewType
    IMAGE: ExtendedTextMessage.PreviewType
    PAYMENT_LINKS: ExtendedTextMessage.PreviewType
    PROFILE: ExtendedTextMessage.PreviewType
    class FontType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SYSTEM: _ClassVar[ExtendedTextMessage.FontType]
        SYSTEM_TEXT: _ClassVar[ExtendedTextMessage.FontType]
        FB_SCRIPT: _ClassVar[ExtendedTextMessage.FontType]
        SYSTEM_BOLD: _ClassVar[ExtendedTextMessage.FontType]
        MORNINGBREEZE_REGULAR: _ClassVar[ExtendedTextMessage.FontType]
        CALISTOGA_REGULAR: _ClassVar[ExtendedTextMessage.FontType]
        EXO2_EXTRABOLD: _ClassVar[ExtendedTextMessage.FontType]
        COURIERPRIME_BOLD: _ClassVar[ExtendedTextMessage.FontType]
    SYSTEM: ExtendedTextMessage.FontType
    SYSTEM_TEXT: ExtendedTextMessage.FontType
    FB_SCRIPT: ExtendedTextMessage.FontType
    SYSTEM_BOLD: ExtendedTextMessage.FontType
    MORNINGBREEZE_REGULAR: ExtendedTextMessage.FontType
    CALISTOGA_REGULAR: ExtendedTextMessage.FontType
    EXO2_EXTRABOLD: ExtendedTextMessage.FontType
    COURIERPRIME_BOLD: ExtendedTextMessage.FontType
    TEXT_FIELD_NUMBER: _ClassVar[int]
    MATCHEDTEXT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    TEXTARGB_FIELD_NUMBER: _ClassVar[int]
    BACKGROUNDARGB_FIELD_NUMBER: _ClassVar[int]
    FONT_FIELD_NUMBER: _ClassVar[int]
    PREVIEWTYPE_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    DONOTPLAYINLINE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILHEIGHT_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILWIDTH_FIELD_NUMBER: _ClassVar[int]
    INVITELINKGROUPTYPE_FIELD_NUMBER: _ClassVar[int]
    INVITELINKPARENTGROUPSUBJECTV2_FIELD_NUMBER: _ClassVar[int]
    INVITELINKPARENTGROUPTHUMBNAILV2_FIELD_NUMBER: _ClassVar[int]
    INVITELINKGROUPTYPEV2_FIELD_NUMBER: _ClassVar[int]
    VIEWONCE_FIELD_NUMBER: _ClassVar[int]
    VIDEOHEIGHT_FIELD_NUMBER: _ClassVar[int]
    VIDEOWIDTH_FIELD_NUMBER: _ClassVar[int]
    FAVICONMMSMETADATA_FIELD_NUMBER: _ClassVar[int]
    LINKPREVIEWMETADATA_FIELD_NUMBER: _ClassVar[int]
    PAYMENTLINKMETADATA_FIELD_NUMBER: _ClassVar[int]
    text: str
    matchedText: str
    description: str
    title: str
    textArgb: int
    backgroundArgb: int
    font: ExtendedTextMessage.FontType
    previewType: ExtendedTextMessage.PreviewType
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    doNotPlayInline: bool
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    mediaKey: bytes
    mediaKeyTimestamp: int
    thumbnailHeight: int
    thumbnailWidth: int
    inviteLinkGroupType: ExtendedTextMessage.InviteLinkGroupType
    inviteLinkParentGroupSubjectV2: str
    inviteLinkParentGroupThumbnailV2: bytes
    inviteLinkGroupTypeV2: ExtendedTextMessage.InviteLinkGroupType
    viewOnce: bool
    videoHeight: int
    videoWidth: int
    faviconMMSMetadata: MMSThumbnailMetadata
    linkPreviewMetadata: LinkPreviewMetadata
    paymentLinkMetadata: PaymentLinkMetadata
    def __init__(self, text: _Optional[str] = ..., matchedText: _Optional[str] = ..., description: _Optional[str] = ..., title: _Optional[str] = ..., textArgb: _Optional[int] = ..., backgroundArgb: _Optional[int] = ..., font: _Optional[_Union[ExtendedTextMessage.FontType, str]] = ..., previewType: _Optional[_Union[ExtendedTextMessage.PreviewType, str]] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., doNotPlayInline: bool = ..., thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., thumbnailHeight: _Optional[int] = ..., thumbnailWidth: _Optional[int] = ..., inviteLinkGroupType: _Optional[_Union[ExtendedTextMessage.InviteLinkGroupType, str]] = ..., inviteLinkParentGroupSubjectV2: _Optional[str] = ..., inviteLinkParentGroupThumbnailV2: _Optional[bytes] = ..., inviteLinkGroupTypeV2: _Optional[_Union[ExtendedTextMessage.InviteLinkGroupType, str]] = ..., viewOnce: bool = ..., videoHeight: _Optional[int] = ..., videoWidth: _Optional[int] = ..., faviconMMSMetadata: _Optional[_Union[MMSThumbnailMetadata, _Mapping]] = ..., linkPreviewMetadata: _Optional[_Union[LinkPreviewMetadata, _Mapping]] = ..., paymentLinkMetadata: _Optional[_Union[PaymentLinkMetadata, _Mapping]] = ...) -> None: ...

class PaymentLinkMetadata(_message.Message):
    __slots__ = ("button", "header")
    class PaymentLinkHeader(_message.Message):
        __slots__ = ("headerType",)
        class PaymentLinkHeaderType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            LINK_PREVIEW: _ClassVar[PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType]
            ORDER: _ClassVar[PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType]
        LINK_PREVIEW: PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType
        ORDER: PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType
        HEADERTYPE_FIELD_NUMBER: _ClassVar[int]
        headerType: PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType
        def __init__(self, headerType: _Optional[_Union[PaymentLinkMetadata.PaymentLinkHeader.PaymentLinkHeaderType, str]] = ...) -> None: ...
    class PaymentLinkButton(_message.Message):
        __slots__ = ("displayText",)
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        displayText: str
        def __init__(self, displayText: _Optional[str] = ...) -> None: ...
    BUTTON_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    button: PaymentLinkMetadata.PaymentLinkButton
    header: PaymentLinkMetadata.PaymentLinkHeader
    def __init__(self, button: _Optional[_Union[PaymentLinkMetadata.PaymentLinkButton, _Mapping]] = ..., header: _Optional[_Union[PaymentLinkMetadata.PaymentLinkHeader, _Mapping]] = ...) -> None: ...

class StatusNotificationMessage(_message.Message):
    __slots__ = ("responseMessageKey", "originalMessageKey", "type")
    class StatusNotificationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[StatusNotificationMessage.StatusNotificationType]
        STATUS_ADD_YOURS: _ClassVar[StatusNotificationMessage.StatusNotificationType]
        STATUS_RESHARE: _ClassVar[StatusNotificationMessage.StatusNotificationType]
    UNKNOWN: StatusNotificationMessage.StatusNotificationType
    STATUS_ADD_YOURS: StatusNotificationMessage.StatusNotificationType
    STATUS_RESHARE: StatusNotificationMessage.StatusNotificationType
    RESPONSEMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ORIGINALMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    responseMessageKey: _WACommon_pb2.MessageKey
    originalMessageKey: _WACommon_pb2.MessageKey
    type: StatusNotificationMessage.StatusNotificationType
    def __init__(self, responseMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., originalMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., type: _Optional[_Union[StatusNotificationMessage.StatusNotificationType, str]] = ...) -> None: ...

class InvoiceMessage(_message.Message):
    __slots__ = ("note", "token", "attachmentType", "attachmentMimetype", "attachmentMediaKey", "attachmentMediaKeyTimestamp", "attachmentFileSHA256", "attachmentFileEncSHA256", "attachmentDirectPath", "attachmentJPEGThumbnail")
    class AttachmentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        IMAGE: _ClassVar[InvoiceMessage.AttachmentType]
        PDF: _ClassVar[InvoiceMessage.AttachmentType]
    IMAGE: InvoiceMessage.AttachmentType
    PDF: InvoiceMessage.AttachmentType
    NOTE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTTYPE_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTMIMETYPE_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTMEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTMEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTFILESHA256_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTFILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTJPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    note: str
    token: str
    attachmentType: InvoiceMessage.AttachmentType
    attachmentMimetype: str
    attachmentMediaKey: bytes
    attachmentMediaKeyTimestamp: int
    attachmentFileSHA256: bytes
    attachmentFileEncSHA256: bytes
    attachmentDirectPath: str
    attachmentJPEGThumbnail: bytes
    def __init__(self, note: _Optional[str] = ..., token: _Optional[str] = ..., attachmentType: _Optional[_Union[InvoiceMessage.AttachmentType, str]] = ..., attachmentMimetype: _Optional[str] = ..., attachmentMediaKey: _Optional[bytes] = ..., attachmentMediaKeyTimestamp: _Optional[int] = ..., attachmentFileSHA256: _Optional[bytes] = ..., attachmentFileEncSHA256: _Optional[bytes] = ..., attachmentDirectPath: _Optional[str] = ..., attachmentJPEGThumbnail: _Optional[bytes] = ...) -> None: ...

class ImageMessage(_message.Message):
    __slots__ = ("URL", "mimetype", "caption", "fileSHA256", "fileLength", "height", "width", "mediaKey", "fileEncSHA256", "interactiveAnnotations", "directPath", "mediaKeyTimestamp", "JPEGThumbnail", "contextInfo", "firstScanSidecar", "firstScanLength", "experimentGroupID", "scansSidecar", "scanLengths", "midQualityFileSHA256", "midQualityFileEncSHA256", "viewOnce", "thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "staticURL", "annotations", "imageSourceType", "accessibilityLabel")
    class ImageSourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        USER_IMAGE: _ClassVar[ImageMessage.ImageSourceType]
        AI_GENERATED: _ClassVar[ImageMessage.ImageSourceType]
        AI_MODIFIED: _ClassVar[ImageMessage.ImageSourceType]
        RASTERIZED_TEXT_STATUS: _ClassVar[ImageMessage.ImageSourceType]
    USER_IMAGE: ImageMessage.ImageSourceType
    AI_GENERATED: ImageMessage.ImageSourceType
    AI_MODIFIED: ImageMessage.ImageSourceType
    RASTERIZED_TEXT_STATUS: ImageMessage.ImageSourceType
    URL_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVEANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    FIRSTSCANSIDECAR_FIELD_NUMBER: _ClassVar[int]
    FIRSTSCANLENGTH_FIELD_NUMBER: _ClassVar[int]
    EXPERIMENTGROUPID_FIELD_NUMBER: _ClassVar[int]
    SCANSSIDECAR_FIELD_NUMBER: _ClassVar[int]
    SCANLENGTHS_FIELD_NUMBER: _ClassVar[int]
    MIDQUALITYFILESHA256_FIELD_NUMBER: _ClassVar[int]
    MIDQUALITYFILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    VIEWONCE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    STATICURL_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    IMAGESOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
    URL: str
    mimetype: str
    caption: str
    fileSHA256: bytes
    fileLength: int
    height: int
    width: int
    mediaKey: bytes
    fileEncSHA256: bytes
    interactiveAnnotations: _containers.RepeatedCompositeFieldContainer[InteractiveAnnotation]
    directPath: str
    mediaKeyTimestamp: int
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    firstScanSidecar: bytes
    firstScanLength: int
    experimentGroupID: int
    scansSidecar: bytes
    scanLengths: _containers.RepeatedScalarFieldContainer[int]
    midQualityFileSHA256: bytes
    midQualityFileEncSHA256: bytes
    viewOnce: bool
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    staticURL: str
    annotations: _containers.RepeatedCompositeFieldContainer[InteractiveAnnotation]
    imageSourceType: ImageMessage.ImageSourceType
    accessibilityLabel: str
    def __init__(self, URL: _Optional[str] = ..., mimetype: _Optional[str] = ..., caption: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., interactiveAnnotations: _Optional[_Iterable[_Union[InteractiveAnnotation, _Mapping]]] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., firstScanSidecar: _Optional[bytes] = ..., firstScanLength: _Optional[int] = ..., experimentGroupID: _Optional[int] = ..., scansSidecar: _Optional[bytes] = ..., scanLengths: _Optional[_Iterable[int]] = ..., midQualityFileSHA256: _Optional[bytes] = ..., midQualityFileEncSHA256: _Optional[bytes] = ..., viewOnce: bool = ..., thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., staticURL: _Optional[str] = ..., annotations: _Optional[_Iterable[_Union[InteractiveAnnotation, _Mapping]]] = ..., imageSourceType: _Optional[_Union[ImageMessage.ImageSourceType, str]] = ..., accessibilityLabel: _Optional[str] = ...) -> None: ...

class ContextInfo(_message.Message):
    __slots__ = ("stanzaID", "participant", "quotedMessage", "remoteJID", "mentionedJID", "conversionSource", "conversionData", "conversionDelaySeconds", "forwardingScore", "isForwarded", "quotedAd", "placeholderKey", "expiration", "ephemeralSettingTimestamp", "ephemeralSharedSecret", "externalAdReply", "entryPointConversionSource", "entryPointConversionApp", "entryPointConversionDelaySeconds", "disappearingMode", "actionLink", "groupSubject", "parentGroupJID", "trustBannerType", "trustBannerAction", "isSampled", "groupMentions", "utm", "forwardedNewsletterMessageInfo", "businessMessageForwardInfo", "smbClientCampaignID", "smbServerCampaignID", "dataSharingContext", "alwaysShowAdAttribution", "featureEligibilities", "entryPointConversionExternalSource", "entryPointConversionExternalMedium", "ctwaSignals", "ctwaPayload", "forwardedAiBotMessageInfo", "statusAttributionType", "urlTrackingMap", "pairedMediaType", "rankingVersion", "memberLabel", "isQuestion", "statusSourceType")
    class StatusSourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        IMAGE: _ClassVar[ContextInfo.StatusSourceType]
        VIDEO: _ClassVar[ContextInfo.StatusSourceType]
        GIF: _ClassVar[ContextInfo.StatusSourceType]
        AUDIO: _ClassVar[ContextInfo.StatusSourceType]
        TEXT: _ClassVar[ContextInfo.StatusSourceType]
        MUSIC_STANDALONE: _ClassVar[ContextInfo.StatusSourceType]
    IMAGE: ContextInfo.StatusSourceType
    VIDEO: ContextInfo.StatusSourceType
    GIF: ContextInfo.StatusSourceType
    AUDIO: ContextInfo.StatusSourceType
    TEXT: ContextInfo.StatusSourceType
    MUSIC_STANDALONE: ContextInfo.StatusSourceType
    class PairedMediaType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NOT_PAIRED_MEDIA: _ClassVar[ContextInfo.PairedMediaType]
        SD_VIDEO_PARENT: _ClassVar[ContextInfo.PairedMediaType]
        HD_VIDEO_CHILD: _ClassVar[ContextInfo.PairedMediaType]
        SD_IMAGE_PARENT: _ClassVar[ContextInfo.PairedMediaType]
        HD_IMAGE_CHILD: _ClassVar[ContextInfo.PairedMediaType]
    NOT_PAIRED_MEDIA: ContextInfo.PairedMediaType
    SD_VIDEO_PARENT: ContextInfo.PairedMediaType
    HD_VIDEO_CHILD: ContextInfo.PairedMediaType
    SD_IMAGE_PARENT: ContextInfo.PairedMediaType
    HD_IMAGE_CHILD: ContextInfo.PairedMediaType
    class StatusAttributionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[ContextInfo.StatusAttributionType]
        RESHARED_FROM_MENTION: _ClassVar[ContextInfo.StatusAttributionType]
        RESHARED_FROM_POST: _ClassVar[ContextInfo.StatusAttributionType]
    NONE: ContextInfo.StatusAttributionType
    RESHARED_FROM_MENTION: ContextInfo.StatusAttributionType
    RESHARED_FROM_POST: ContextInfo.StatusAttributionType
    class ForwardedNewsletterMessageInfo(_message.Message):
        __slots__ = ("newsletterJID", "serverMessageID", "newsletterName", "contentType", "accessibilityText")
        class ContentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UPDATE: _ClassVar[ContextInfo.ForwardedNewsletterMessageInfo.ContentType]
            UPDATE_CARD: _ClassVar[ContextInfo.ForwardedNewsletterMessageInfo.ContentType]
            LINK_CARD: _ClassVar[ContextInfo.ForwardedNewsletterMessageInfo.ContentType]
        UPDATE: ContextInfo.ForwardedNewsletterMessageInfo.ContentType
        UPDATE_CARD: ContextInfo.ForwardedNewsletterMessageInfo.ContentType
        LINK_CARD: ContextInfo.ForwardedNewsletterMessageInfo.ContentType
        NEWSLETTERJID_FIELD_NUMBER: _ClassVar[int]
        SERVERMESSAGEID_FIELD_NUMBER: _ClassVar[int]
        NEWSLETTERNAME_FIELD_NUMBER: _ClassVar[int]
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        ACCESSIBILITYTEXT_FIELD_NUMBER: _ClassVar[int]
        newsletterJID: str
        serverMessageID: int
        newsletterName: str
        contentType: ContextInfo.ForwardedNewsletterMessageInfo.ContentType
        accessibilityText: str
        def __init__(self, newsletterJID: _Optional[str] = ..., serverMessageID: _Optional[int] = ..., newsletterName: _Optional[str] = ..., contentType: _Optional[_Union[ContextInfo.ForwardedNewsletterMessageInfo.ContentType, str]] = ..., accessibilityText: _Optional[str] = ...) -> None: ...
    class ExternalAdReplyInfo(_message.Message):
        __slots__ = ("title", "body", "mediaType", "thumbnailURL", "mediaURL", "thumbnail", "sourceType", "sourceID", "sourceURL", "containsAutoReply", "renderLargerThumbnail", "showAdAttribution", "ctwaClid", "ref", "clickToWhatsappCall", "adContextPreviewDismissed", "sourceApp", "automatedGreetingMessageShown", "greetingMessageBody", "ctaPayload", "disableNudge", "originalImageURL", "automatedGreetingMessageCtaType", "wtwaAdFormat", "adType")
        class AdType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            CTWA: _ClassVar[ContextInfo.ExternalAdReplyInfo.AdType]
            CAWC: _ClassVar[ContextInfo.ExternalAdReplyInfo.AdType]
        CTWA: ContextInfo.ExternalAdReplyInfo.AdType
        CAWC: ContextInfo.ExternalAdReplyInfo.AdType
        class MediaType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NONE: _ClassVar[ContextInfo.ExternalAdReplyInfo.MediaType]
            IMAGE: _ClassVar[ContextInfo.ExternalAdReplyInfo.MediaType]
            VIDEO: _ClassVar[ContextInfo.ExternalAdReplyInfo.MediaType]
        NONE: ContextInfo.ExternalAdReplyInfo.MediaType
        IMAGE: ContextInfo.ExternalAdReplyInfo.MediaType
        VIDEO: ContextInfo.ExternalAdReplyInfo.MediaType
        TITLE_FIELD_NUMBER: _ClassVar[int]
        BODY_FIELD_NUMBER: _ClassVar[int]
        MEDIATYPE_FIELD_NUMBER: _ClassVar[int]
        THUMBNAILURL_FIELD_NUMBER: _ClassVar[int]
        MEDIAURL_FIELD_NUMBER: _ClassVar[int]
        THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        SOURCETYPE_FIELD_NUMBER: _ClassVar[int]
        SOURCEID_FIELD_NUMBER: _ClassVar[int]
        SOURCEURL_FIELD_NUMBER: _ClassVar[int]
        CONTAINSAUTOREPLY_FIELD_NUMBER: _ClassVar[int]
        RENDERLARGERTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        SHOWADATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
        CTWACLID_FIELD_NUMBER: _ClassVar[int]
        REF_FIELD_NUMBER: _ClassVar[int]
        CLICKTOWHATSAPPCALL_FIELD_NUMBER: _ClassVar[int]
        ADCONTEXTPREVIEWDISMISSED_FIELD_NUMBER: _ClassVar[int]
        SOURCEAPP_FIELD_NUMBER: _ClassVar[int]
        AUTOMATEDGREETINGMESSAGESHOWN_FIELD_NUMBER: _ClassVar[int]
        GREETINGMESSAGEBODY_FIELD_NUMBER: _ClassVar[int]
        CTAPAYLOAD_FIELD_NUMBER: _ClassVar[int]
        DISABLENUDGE_FIELD_NUMBER: _ClassVar[int]
        ORIGINALIMAGEURL_FIELD_NUMBER: _ClassVar[int]
        AUTOMATEDGREETINGMESSAGECTATYPE_FIELD_NUMBER: _ClassVar[int]
        WTWAADFORMAT_FIELD_NUMBER: _ClassVar[int]
        ADTYPE_FIELD_NUMBER: _ClassVar[int]
        title: str
        body: str
        mediaType: ContextInfo.ExternalAdReplyInfo.MediaType
        thumbnailURL: str
        mediaURL: str
        thumbnail: bytes
        sourceType: str
        sourceID: str
        sourceURL: str
        containsAutoReply: bool
        renderLargerThumbnail: bool
        showAdAttribution: bool
        ctwaClid: str
        ref: str
        clickToWhatsappCall: bool
        adContextPreviewDismissed: bool
        sourceApp: str
        automatedGreetingMessageShown: bool
        greetingMessageBody: str
        ctaPayload: str
        disableNudge: bool
        originalImageURL: str
        automatedGreetingMessageCtaType: str
        wtwaAdFormat: bool
        adType: ContextInfo.ExternalAdReplyInfo.AdType
        def __init__(self, title: _Optional[str] = ..., body: _Optional[str] = ..., mediaType: _Optional[_Union[ContextInfo.ExternalAdReplyInfo.MediaType, str]] = ..., thumbnailURL: _Optional[str] = ..., mediaURL: _Optional[str] = ..., thumbnail: _Optional[bytes] = ..., sourceType: _Optional[str] = ..., sourceID: _Optional[str] = ..., sourceURL: _Optional[str] = ..., containsAutoReply: bool = ..., renderLargerThumbnail: bool = ..., showAdAttribution: bool = ..., ctwaClid: _Optional[str] = ..., ref: _Optional[str] = ..., clickToWhatsappCall: bool = ..., adContextPreviewDismissed: bool = ..., sourceApp: _Optional[str] = ..., automatedGreetingMessageShown: bool = ..., greetingMessageBody: _Optional[str] = ..., ctaPayload: _Optional[str] = ..., disableNudge: bool = ..., originalImageURL: _Optional[str] = ..., automatedGreetingMessageCtaType: _Optional[str] = ..., wtwaAdFormat: bool = ..., adType: _Optional[_Union[ContextInfo.ExternalAdReplyInfo.AdType, str]] = ...) -> None: ...
    class AdReplyInfo(_message.Message):
        __slots__ = ("advertiserName", "mediaType", "JPEGThumbnail", "caption")
        class MediaType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NONE: _ClassVar[ContextInfo.AdReplyInfo.MediaType]
            IMAGE: _ClassVar[ContextInfo.AdReplyInfo.MediaType]
            VIDEO: _ClassVar[ContextInfo.AdReplyInfo.MediaType]
        NONE: ContextInfo.AdReplyInfo.MediaType
        IMAGE: ContextInfo.AdReplyInfo.MediaType
        VIDEO: ContextInfo.AdReplyInfo.MediaType
        ADVERTISERNAME_FIELD_NUMBER: _ClassVar[int]
        MEDIATYPE_FIELD_NUMBER: _ClassVar[int]
        JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        advertiserName: str
        mediaType: ContextInfo.AdReplyInfo.MediaType
        JPEGThumbnail: bytes
        caption: str
        def __init__(self, advertiserName: _Optional[str] = ..., mediaType: _Optional[_Union[ContextInfo.AdReplyInfo.MediaType, str]] = ..., JPEGThumbnail: _Optional[bytes] = ..., caption: _Optional[str] = ...) -> None: ...
    class FeatureEligibilities(_message.Message):
        __slots__ = ("cannotBeReactedTo", "cannotBeRanked", "canRequestFeedback", "canBeReshared")
        CANNOTBEREACTEDTO_FIELD_NUMBER: _ClassVar[int]
        CANNOTBERANKED_FIELD_NUMBER: _ClassVar[int]
        CANREQUESTFEEDBACK_FIELD_NUMBER: _ClassVar[int]
        CANBERESHARED_FIELD_NUMBER: _ClassVar[int]
        cannotBeReactedTo: bool
        cannotBeRanked: bool
        canRequestFeedback: bool
        canBeReshared: bool
        def __init__(self, cannotBeReactedTo: bool = ..., cannotBeRanked: bool = ..., canRequestFeedback: bool = ..., canBeReshared: bool = ...) -> None: ...
    class DataSharingContext(_message.Message):
        __slots__ = ("showMmDisclosure", "encryptedSignalTokenConsented", "parameters")
        class Parameters(_message.Message):
            __slots__ = ("key", "stringData", "intData", "floatData", "contents")
            KEY_FIELD_NUMBER: _ClassVar[int]
            STRINGDATA_FIELD_NUMBER: _ClassVar[int]
            INTDATA_FIELD_NUMBER: _ClassVar[int]
            FLOATDATA_FIELD_NUMBER: _ClassVar[int]
            CONTENTS_FIELD_NUMBER: _ClassVar[int]
            key: str
            stringData: str
            intData: int
            floatData: float
            contents: ContextInfo.DataSharingContext.Parameters
            def __init__(self, key: _Optional[str] = ..., stringData: _Optional[str] = ..., intData: _Optional[int] = ..., floatData: _Optional[float] = ..., contents: _Optional[_Union[ContextInfo.DataSharingContext.Parameters, _Mapping]] = ...) -> None: ...
        SHOWMMDISCLOSURE_FIELD_NUMBER: _ClassVar[int]
        ENCRYPTEDSIGNALTOKENCONSENTED_FIELD_NUMBER: _ClassVar[int]
        PARAMETERS_FIELD_NUMBER: _ClassVar[int]
        showMmDisclosure: bool
        encryptedSignalTokenConsented: str
        parameters: _containers.RepeatedCompositeFieldContainer[ContextInfo.DataSharingContext.Parameters]
        def __init__(self, showMmDisclosure: bool = ..., encryptedSignalTokenConsented: _Optional[str] = ..., parameters: _Optional[_Iterable[_Union[ContextInfo.DataSharingContext.Parameters, _Mapping]]] = ...) -> None: ...
    class ForwardedAIBotMessageInfo(_message.Message):
        __slots__ = ("botName", "botJID", "creatorName")
        BOTNAME_FIELD_NUMBER: _ClassVar[int]
        BOTJID_FIELD_NUMBER: _ClassVar[int]
        CREATORNAME_FIELD_NUMBER: _ClassVar[int]
        botName: str
        botJID: str
        creatorName: str
        def __init__(self, botName: _Optional[str] = ..., botJID: _Optional[str] = ..., creatorName: _Optional[str] = ...) -> None: ...
    class UTMInfo(_message.Message):
        __slots__ = ("utmSource", "utmCampaign")
        UTMSOURCE_FIELD_NUMBER: _ClassVar[int]
        UTMCAMPAIGN_FIELD_NUMBER: _ClassVar[int]
        utmSource: str
        utmCampaign: str
        def __init__(self, utmSource: _Optional[str] = ..., utmCampaign: _Optional[str] = ...) -> None: ...
    class BusinessMessageForwardInfo(_message.Message):
        __slots__ = ("businessOwnerJID",)
        BUSINESSOWNERJID_FIELD_NUMBER: _ClassVar[int]
        businessOwnerJID: str
        def __init__(self, businessOwnerJID: _Optional[str] = ...) -> None: ...
    STANZAID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_FIELD_NUMBER: _ClassVar[int]
    QUOTEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REMOTEJID_FIELD_NUMBER: _ClassVar[int]
    MENTIONEDJID_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONSOURCE_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONDATA_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONDELAYSECONDS_FIELD_NUMBER: _ClassVar[int]
    FORWARDINGSCORE_FIELD_NUMBER: _ClassVar[int]
    ISFORWARDED_FIELD_NUMBER: _ClassVar[int]
    QUOTEDAD_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDERKEY_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALSHAREDSECRET_FIELD_NUMBER: _ClassVar[int]
    EXTERNALADREPLY_FIELD_NUMBER: _ClassVar[int]
    ENTRYPOINTCONVERSIONSOURCE_FIELD_NUMBER: _ClassVar[int]
    ENTRYPOINTCONVERSIONAPP_FIELD_NUMBER: _ClassVar[int]
    ENTRYPOINTCONVERSIONDELAYSECONDS_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMODE_FIELD_NUMBER: _ClassVar[int]
    ACTIONLINK_FIELD_NUMBER: _ClassVar[int]
    GROUPSUBJECT_FIELD_NUMBER: _ClassVar[int]
    PARENTGROUPJID_FIELD_NUMBER: _ClassVar[int]
    TRUSTBANNERTYPE_FIELD_NUMBER: _ClassVar[int]
    TRUSTBANNERACTION_FIELD_NUMBER: _ClassVar[int]
    ISSAMPLED_FIELD_NUMBER: _ClassVar[int]
    GROUPMENTIONS_FIELD_NUMBER: _ClassVar[int]
    UTM_FIELD_NUMBER: _ClassVar[int]
    FORWARDEDNEWSLETTERMESSAGEINFO_FIELD_NUMBER: _ClassVar[int]
    BUSINESSMESSAGEFORWARDINFO_FIELD_NUMBER: _ClassVar[int]
    SMBCLIENTCAMPAIGNID_FIELD_NUMBER: _ClassVar[int]
    SMBSERVERCAMPAIGNID_FIELD_NUMBER: _ClassVar[int]
    DATASHARINGCONTEXT_FIELD_NUMBER: _ClassVar[int]
    ALWAYSSHOWADATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
    FEATUREELIGIBILITIES_FIELD_NUMBER: _ClassVar[int]
    ENTRYPOINTCONVERSIONEXTERNALSOURCE_FIELD_NUMBER: _ClassVar[int]
    ENTRYPOINTCONVERSIONEXTERNALMEDIUM_FIELD_NUMBER: _ClassVar[int]
    CTWASIGNALS_FIELD_NUMBER: _ClassVar[int]
    CTWAPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    FORWARDEDAIBOTMESSAGEINFO_FIELD_NUMBER: _ClassVar[int]
    STATUSATTRIBUTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    URLTRACKINGMAP_FIELD_NUMBER: _ClassVar[int]
    PAIREDMEDIATYPE_FIELD_NUMBER: _ClassVar[int]
    RANKINGVERSION_FIELD_NUMBER: _ClassVar[int]
    MEMBERLABEL_FIELD_NUMBER: _ClassVar[int]
    ISQUESTION_FIELD_NUMBER: _ClassVar[int]
    STATUSSOURCETYPE_FIELD_NUMBER: _ClassVar[int]
    stanzaID: str
    participant: str
    quotedMessage: Message
    remoteJID: str
    mentionedJID: _containers.RepeatedScalarFieldContainer[str]
    conversionSource: str
    conversionData: bytes
    conversionDelaySeconds: int
    forwardingScore: int
    isForwarded: bool
    quotedAd: ContextInfo.AdReplyInfo
    placeholderKey: _WACommon_pb2.MessageKey
    expiration: int
    ephemeralSettingTimestamp: int
    ephemeralSharedSecret: bytes
    externalAdReply: ContextInfo.ExternalAdReplyInfo
    entryPointConversionSource: str
    entryPointConversionApp: str
    entryPointConversionDelaySeconds: int
    disappearingMode: DisappearingMode
    actionLink: ActionLink
    groupSubject: str
    parentGroupJID: str
    trustBannerType: str
    trustBannerAction: int
    isSampled: bool
    groupMentions: _containers.RepeatedCompositeFieldContainer[GroupMention]
    utm: ContextInfo.UTMInfo
    forwardedNewsletterMessageInfo: ContextInfo.ForwardedNewsletterMessageInfo
    businessMessageForwardInfo: ContextInfo.BusinessMessageForwardInfo
    smbClientCampaignID: str
    smbServerCampaignID: str
    dataSharingContext: ContextInfo.DataSharingContext
    alwaysShowAdAttribution: bool
    featureEligibilities: ContextInfo.FeatureEligibilities
    entryPointConversionExternalSource: str
    entryPointConversionExternalMedium: str
    ctwaSignals: str
    ctwaPayload: bytes
    forwardedAiBotMessageInfo: ContextInfo.ForwardedAIBotMessageInfo
    statusAttributionType: ContextInfo.StatusAttributionType
    urlTrackingMap: UrlTrackingMap
    pairedMediaType: ContextInfo.PairedMediaType
    rankingVersion: int
    memberLabel: MemberLabel
    isQuestion: bool
    statusSourceType: ContextInfo.StatusSourceType
    def __init__(self, stanzaID: _Optional[str] = ..., participant: _Optional[str] = ..., quotedMessage: _Optional[_Union[Message, _Mapping]] = ..., remoteJID: _Optional[str] = ..., mentionedJID: _Optional[_Iterable[str]] = ..., conversionSource: _Optional[str] = ..., conversionData: _Optional[bytes] = ..., conversionDelaySeconds: _Optional[int] = ..., forwardingScore: _Optional[int] = ..., isForwarded: bool = ..., quotedAd: _Optional[_Union[ContextInfo.AdReplyInfo, _Mapping]] = ..., placeholderKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., expiration: _Optional[int] = ..., ephemeralSettingTimestamp: _Optional[int] = ..., ephemeralSharedSecret: _Optional[bytes] = ..., externalAdReply: _Optional[_Union[ContextInfo.ExternalAdReplyInfo, _Mapping]] = ..., entryPointConversionSource: _Optional[str] = ..., entryPointConversionApp: _Optional[str] = ..., entryPointConversionDelaySeconds: _Optional[int] = ..., disappearingMode: _Optional[_Union[DisappearingMode, _Mapping]] = ..., actionLink: _Optional[_Union[ActionLink, _Mapping]] = ..., groupSubject: _Optional[str] = ..., parentGroupJID: _Optional[str] = ..., trustBannerType: _Optional[str] = ..., trustBannerAction: _Optional[int] = ..., isSampled: bool = ..., groupMentions: _Optional[_Iterable[_Union[GroupMention, _Mapping]]] = ..., utm: _Optional[_Union[ContextInfo.UTMInfo, _Mapping]] = ..., forwardedNewsletterMessageInfo: _Optional[_Union[ContextInfo.ForwardedNewsletterMessageInfo, _Mapping]] = ..., businessMessageForwardInfo: _Optional[_Union[ContextInfo.BusinessMessageForwardInfo, _Mapping]] = ..., smbClientCampaignID: _Optional[str] = ..., smbServerCampaignID: _Optional[str] = ..., dataSharingContext: _Optional[_Union[ContextInfo.DataSharingContext, _Mapping]] = ..., alwaysShowAdAttribution: bool = ..., featureEligibilities: _Optional[_Union[ContextInfo.FeatureEligibilities, _Mapping]] = ..., entryPointConversionExternalSource: _Optional[str] = ..., entryPointConversionExternalMedium: _Optional[str] = ..., ctwaSignals: _Optional[str] = ..., ctwaPayload: _Optional[bytes] = ..., forwardedAiBotMessageInfo: _Optional[_Union[ContextInfo.ForwardedAIBotMessageInfo, _Mapping]] = ..., statusAttributionType: _Optional[_Union[ContextInfo.StatusAttributionType, str]] = ..., urlTrackingMap: _Optional[_Union[UrlTrackingMap, _Mapping]] = ..., pairedMediaType: _Optional[_Union[ContextInfo.PairedMediaType, str]] = ..., rankingVersion: _Optional[int] = ..., memberLabel: _Optional[_Union[MemberLabel, _Mapping]] = ..., isQuestion: bool = ..., statusSourceType: _Optional[_Union[ContextInfo.StatusSourceType, str]] = ...) -> None: ...

class BotPluginMetadata(_message.Message):
    __slots__ = ("provider", "pluginType", "thumbnailCDNURL", "profilePhotoCDNURL", "searchProviderURL", "referenceIndex", "expectedLinksCount", "searchQuery", "parentPluginMessageKey", "deprecatedField", "parentPluginType", "faviconCDNURL")
    class PluginType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_PLUGIN: _ClassVar[BotPluginMetadata.PluginType]
        REELS: _ClassVar[BotPluginMetadata.PluginType]
        SEARCH: _ClassVar[BotPluginMetadata.PluginType]
    UNKNOWN_PLUGIN: BotPluginMetadata.PluginType
    REELS: BotPluginMetadata.PluginType
    SEARCH: BotPluginMetadata.PluginType
    class SearchProvider(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[BotPluginMetadata.SearchProvider]
        BING: _ClassVar[BotPluginMetadata.SearchProvider]
        GOOGLE: _ClassVar[BotPluginMetadata.SearchProvider]
        SUPPORT: _ClassVar[BotPluginMetadata.SearchProvider]
    UNKNOWN: BotPluginMetadata.SearchProvider
    BING: BotPluginMetadata.SearchProvider
    GOOGLE: BotPluginMetadata.SearchProvider
    SUPPORT: BotPluginMetadata.SearchProvider
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    PLUGINTYPE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILCDNURL_FIELD_NUMBER: _ClassVar[int]
    PROFILEPHOTOCDNURL_FIELD_NUMBER: _ClassVar[int]
    SEARCHPROVIDERURL_FIELD_NUMBER: _ClassVar[int]
    REFERENCEINDEX_FIELD_NUMBER: _ClassVar[int]
    EXPECTEDLINKSCOUNT_FIELD_NUMBER: _ClassVar[int]
    SEARCHQUERY_FIELD_NUMBER: _ClassVar[int]
    PARENTPLUGINMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDFIELD_FIELD_NUMBER: _ClassVar[int]
    PARENTPLUGINTYPE_FIELD_NUMBER: _ClassVar[int]
    FAVICONCDNURL_FIELD_NUMBER: _ClassVar[int]
    provider: BotPluginMetadata.SearchProvider
    pluginType: BotPluginMetadata.PluginType
    thumbnailCDNURL: str
    profilePhotoCDNURL: str
    searchProviderURL: str
    referenceIndex: int
    expectedLinksCount: int
    searchQuery: str
    parentPluginMessageKey: _WACommon_pb2.MessageKey
    deprecatedField: BotPluginMetadata.PluginType
    parentPluginType: BotPluginMetadata.PluginType
    faviconCDNURL: str
    def __init__(self, provider: _Optional[_Union[BotPluginMetadata.SearchProvider, str]] = ..., pluginType: _Optional[_Union[BotPluginMetadata.PluginType, str]] = ..., thumbnailCDNURL: _Optional[str] = ..., profilePhotoCDNURL: _Optional[str] = ..., searchProviderURL: _Optional[str] = ..., referenceIndex: _Optional[int] = ..., expectedLinksCount: _Optional[int] = ..., searchQuery: _Optional[str] = ..., parentPluginMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., deprecatedField: _Optional[_Union[BotPluginMetadata.PluginType, str]] = ..., parentPluginType: _Optional[_Union[BotPluginMetadata.PluginType, str]] = ..., faviconCDNURL: _Optional[str] = ...) -> None: ...

class BotLinkedAccount(_message.Message):
    __slots__ = ("type",)
    class BotLinkedAccountType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BOT_LINKED_ACCOUNT_TYPE_1P: _ClassVar[BotLinkedAccount.BotLinkedAccountType]
    BOT_LINKED_ACCOUNT_TYPE_1P: BotLinkedAccount.BotLinkedAccountType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: BotLinkedAccount.BotLinkedAccountType
    def __init__(self, type: _Optional[_Union[BotLinkedAccount.BotLinkedAccountType, str]] = ...) -> None: ...

class AIRichResponseMessage(_message.Message):
    __slots__ = ("messageType", "submessages", "unifiedResponse")
    class AIRichResponseSubMessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        AI_RICH_RESPONSE_UNKNOWN: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_GRID_IMAGE: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_TEXT: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_INLINE_IMAGE: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_TABLE: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_CODE: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_DYNAMIC: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_MAP: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_LATEX: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
        AI_RICH_RESPONSE_CONTENT_ITEMS: _ClassVar[AIRichResponseMessage.AIRichResponseSubMessageType]
    AI_RICH_RESPONSE_UNKNOWN: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_GRID_IMAGE: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_TEXT: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_INLINE_IMAGE: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_TABLE: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_CODE: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_DYNAMIC: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_MAP: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_LATEX: AIRichResponseMessage.AIRichResponseSubMessageType
    AI_RICH_RESPONSE_CONTENT_ITEMS: AIRichResponseMessage.AIRichResponseSubMessageType
    class AIRichResponseMessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        AI_RICH_RESPONSE_TYPE_UNKNOWN: _ClassVar[AIRichResponseMessage.AIRichResponseMessageType]
        AI_RICH_RESPONSE_TYPE_STANDARD: _ClassVar[AIRichResponseMessage.AIRichResponseMessageType]
    AI_RICH_RESPONSE_TYPE_UNKNOWN: AIRichResponseMessage.AIRichResponseMessageType
    AI_RICH_RESPONSE_TYPE_STANDARD: AIRichResponseMessage.AIRichResponseMessageType
    class AIRichResponseContentItemsMetadata(_message.Message):
        __slots__ = ("itemsMetadata", "contentType")
        class ContentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DEFAULT: _ClassVar[AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType]
            CAROUSEL: _ClassVar[AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType]
        DEFAULT: AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType
        CAROUSEL: AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType
        class AIRichResponseContentItemMetadata(_message.Message):
            __slots__ = ("reelItem",)
            REELITEM_FIELD_NUMBER: _ClassVar[int]
            reelItem: AIRichResponseMessage.AIRichResponseContentItemsMetadata.AIRichResponseReelItem
            def __init__(self, reelItem: _Optional[_Union[AIRichResponseMessage.AIRichResponseContentItemsMetadata.AIRichResponseReelItem, _Mapping]] = ...) -> None: ...
        class AIRichResponseReelItem(_message.Message):
            __slots__ = ("title", "profileIconURL", "thumbnailURL", "videoURL")
            TITLE_FIELD_NUMBER: _ClassVar[int]
            PROFILEICONURL_FIELD_NUMBER: _ClassVar[int]
            THUMBNAILURL_FIELD_NUMBER: _ClassVar[int]
            VIDEOURL_FIELD_NUMBER: _ClassVar[int]
            title: str
            profileIconURL: str
            thumbnailURL: str
            videoURL: str
            def __init__(self, title: _Optional[str] = ..., profileIconURL: _Optional[str] = ..., thumbnailURL: _Optional[str] = ..., videoURL: _Optional[str] = ...) -> None: ...
        ITEMSMETADATA_FIELD_NUMBER: _ClassVar[int]
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        itemsMetadata: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseContentItemsMetadata.AIRichResponseContentItemMetadata]
        contentType: AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType
        def __init__(self, itemsMetadata: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseContentItemsMetadata.AIRichResponseContentItemMetadata, _Mapping]]] = ..., contentType: _Optional[_Union[AIRichResponseMessage.AIRichResponseContentItemsMetadata.ContentType, str]] = ...) -> None: ...
    class AIRichResponseDynamicMetadata(_message.Message):
        __slots__ = ("type", "version", "URL", "loopCount")
        class AIRichResponseDynamicMetadataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_UNKNOWN: _ClassVar[AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType]
            AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_IMAGE: _ClassVar[AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType]
            AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_GIF: _ClassVar[AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType]
        AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_UNKNOWN: AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType
        AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_IMAGE: AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType
        AI_RICH_RESPONSE_DYNAMIC_METADATA_TYPE_GIF: AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType
        TYPE_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        URL_FIELD_NUMBER: _ClassVar[int]
        LOOPCOUNT_FIELD_NUMBER: _ClassVar[int]
        type: AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType
        version: int
        URL: str
        loopCount: int
        def __init__(self, type: _Optional[_Union[AIRichResponseMessage.AIRichResponseDynamicMetadata.AIRichResponseDynamicMetadataType, str]] = ..., version: _Optional[int] = ..., URL: _Optional[str] = ..., loopCount: _Optional[int] = ...) -> None: ...
    class AIRichResponseCodeMetadata(_message.Message):
        __slots__ = ("codeLanguage", "codeBlocks")
        class AIRichResponseCodeHighlightType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_DEFAULT: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_KEYWORD: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_METHOD: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_STRING: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_NUMBER: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
            AI_RICH_RESPONSE_CODE_HIGHLIGHT_COMMENT: _ClassVar[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType]
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_DEFAULT: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_KEYWORD: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_METHOD: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_STRING: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_NUMBER: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        AI_RICH_RESPONSE_CODE_HIGHLIGHT_COMMENT: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
        class AIRichResponseCodeBlock(_message.Message):
            __slots__ = ("highlightType", "codeContent")
            HIGHLIGHTTYPE_FIELD_NUMBER: _ClassVar[int]
            CODECONTENT_FIELD_NUMBER: _ClassVar[int]
            highlightType: AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType
            codeContent: str
            def __init__(self, highlightType: _Optional[_Union[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeHighlightType, str]] = ..., codeContent: _Optional[str] = ...) -> None: ...
        CODELANGUAGE_FIELD_NUMBER: _ClassVar[int]
        CODEBLOCKS_FIELD_NUMBER: _ClassVar[int]
        codeLanguage: str
        codeBlocks: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeBlock]
        def __init__(self, codeLanguage: _Optional[str] = ..., codeBlocks: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseCodeMetadata.AIRichResponseCodeBlock, _Mapping]]] = ...) -> None: ...
    class AIRichResponseInlineImageMetadata(_message.Message):
        __slots__ = ("imageURL", "imageText", "alignment", "tapLinkURL")
        class AIRichResponseImageAlignment(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            AI_RICH_RESPONSE_IMAGE_LAYOUT_LEADING_ALIGNED: _ClassVar[AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment]
            AI_RICH_RESPONSE_IMAGE_LAYOUT_TRAILING_ALIGNED: _ClassVar[AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment]
            AI_RICH_RESPONSE_IMAGE_LAYOUT_CENTER_ALIGNED: _ClassVar[AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment]
        AI_RICH_RESPONSE_IMAGE_LAYOUT_LEADING_ALIGNED: AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment
        AI_RICH_RESPONSE_IMAGE_LAYOUT_TRAILING_ALIGNED: AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment
        AI_RICH_RESPONSE_IMAGE_LAYOUT_CENTER_ALIGNED: AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment
        IMAGEURL_FIELD_NUMBER: _ClassVar[int]
        IMAGETEXT_FIELD_NUMBER: _ClassVar[int]
        ALIGNMENT_FIELD_NUMBER: _ClassVar[int]
        TAPLINKURL_FIELD_NUMBER: _ClassVar[int]
        imageURL: AIRichResponseMessage.AIRichResponseImageURL
        imageText: str
        alignment: AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment
        tapLinkURL: str
        def __init__(self, imageURL: _Optional[_Union[AIRichResponseMessage.AIRichResponseImageURL, _Mapping]] = ..., imageText: _Optional[str] = ..., alignment: _Optional[_Union[AIRichResponseMessage.AIRichResponseInlineImageMetadata.AIRichResponseImageAlignment, str]] = ..., tapLinkURL: _Optional[str] = ...) -> None: ...
    class AIRichResponseSubMessage(_message.Message):
        __slots__ = ("messageType", "gridImageMetadata", "messageText", "imageMetadata", "codeMetadata", "tableMetadata", "dynamicMetadata", "latexMetadata", "mapMetadata", "contentItemsMetadata")
        MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
        GRIDIMAGEMETADATA_FIELD_NUMBER: _ClassVar[int]
        MESSAGETEXT_FIELD_NUMBER: _ClassVar[int]
        IMAGEMETADATA_FIELD_NUMBER: _ClassVar[int]
        CODEMETADATA_FIELD_NUMBER: _ClassVar[int]
        TABLEMETADATA_FIELD_NUMBER: _ClassVar[int]
        DYNAMICMETADATA_FIELD_NUMBER: _ClassVar[int]
        LATEXMETADATA_FIELD_NUMBER: _ClassVar[int]
        MAPMETADATA_FIELD_NUMBER: _ClassVar[int]
        CONTENTITEMSMETADATA_FIELD_NUMBER: _ClassVar[int]
        messageType: AIRichResponseMessage.AIRichResponseSubMessageType
        gridImageMetadata: AIRichResponseMessage.AIRichResponseGridImageMetadata
        messageText: str
        imageMetadata: AIRichResponseMessage.AIRichResponseInlineImageMetadata
        codeMetadata: AIRichResponseMessage.AIRichResponseCodeMetadata
        tableMetadata: AIRichResponseMessage.AIRichResponseTableMetadata
        dynamicMetadata: AIRichResponseMessage.AIRichResponseDynamicMetadata
        latexMetadata: AIRichResponseMessage.AIRichResponseLatexMetadata
        mapMetadata: AIRichResponseMessage.AIRichResponseMapMetadata
        contentItemsMetadata: AIRichResponseMessage.AIRichResponseContentItemsMetadata
        def __init__(self, messageType: _Optional[_Union[AIRichResponseMessage.AIRichResponseSubMessageType, str]] = ..., gridImageMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseGridImageMetadata, _Mapping]] = ..., messageText: _Optional[str] = ..., imageMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseInlineImageMetadata, _Mapping]] = ..., codeMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseCodeMetadata, _Mapping]] = ..., tableMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseTableMetadata, _Mapping]] = ..., dynamicMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseDynamicMetadata, _Mapping]] = ..., latexMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseLatexMetadata, _Mapping]] = ..., mapMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseMapMetadata, _Mapping]] = ..., contentItemsMetadata: _Optional[_Union[AIRichResponseMessage.AIRichResponseContentItemsMetadata, _Mapping]] = ...) -> None: ...
    class AIRichResponseMapMetadata(_message.Message):
        __slots__ = ("centerLatitude", "centerLongitude", "latitudeDelta", "longitudeDelta", "annotations", "showInfoList")
        class AIRichResponseMapAnnotation(_message.Message):
            __slots__ = ("annotationNumber", "latitude", "longitude", "title", "body")
            ANNOTATIONNUMBER_FIELD_NUMBER: _ClassVar[int]
            LATITUDE_FIELD_NUMBER: _ClassVar[int]
            LONGITUDE_FIELD_NUMBER: _ClassVar[int]
            TITLE_FIELD_NUMBER: _ClassVar[int]
            BODY_FIELD_NUMBER: _ClassVar[int]
            annotationNumber: int
            latitude: float
            longitude: float
            title: str
            body: str
            def __init__(self, annotationNumber: _Optional[int] = ..., latitude: _Optional[float] = ..., longitude: _Optional[float] = ..., title: _Optional[str] = ..., body: _Optional[str] = ...) -> None: ...
        CENTERLATITUDE_FIELD_NUMBER: _ClassVar[int]
        CENTERLONGITUDE_FIELD_NUMBER: _ClassVar[int]
        LATITUDEDELTA_FIELD_NUMBER: _ClassVar[int]
        LONGITUDEDELTA_FIELD_NUMBER: _ClassVar[int]
        ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
        SHOWINFOLIST_FIELD_NUMBER: _ClassVar[int]
        centerLatitude: float
        centerLongitude: float
        latitudeDelta: float
        longitudeDelta: float
        annotations: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseMapMetadata.AIRichResponseMapAnnotation]
        showInfoList: bool
        def __init__(self, centerLatitude: _Optional[float] = ..., centerLongitude: _Optional[float] = ..., latitudeDelta: _Optional[float] = ..., longitudeDelta: _Optional[float] = ..., annotations: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseMapMetadata.AIRichResponseMapAnnotation, _Mapping]]] = ..., showInfoList: bool = ...) -> None: ...
    class AIRichResponseLatexMetadata(_message.Message):
        __slots__ = ("text", "expressions")
        class AIRichResponseLatexExpression(_message.Message):
            __slots__ = ("latexExpression", "URL", "width", "height", "fontHeight", "imageTopPadding", "imageLeadingPadding", "imageBottomPadding", "imageTrailingPadding")
            LATEXEXPRESSION_FIELD_NUMBER: _ClassVar[int]
            URL_FIELD_NUMBER: _ClassVar[int]
            WIDTH_FIELD_NUMBER: _ClassVar[int]
            HEIGHT_FIELD_NUMBER: _ClassVar[int]
            FONTHEIGHT_FIELD_NUMBER: _ClassVar[int]
            IMAGETOPPADDING_FIELD_NUMBER: _ClassVar[int]
            IMAGELEADINGPADDING_FIELD_NUMBER: _ClassVar[int]
            IMAGEBOTTOMPADDING_FIELD_NUMBER: _ClassVar[int]
            IMAGETRAILINGPADDING_FIELD_NUMBER: _ClassVar[int]
            latexExpression: str
            URL: str
            width: float
            height: float
            fontHeight: float
            imageTopPadding: float
            imageLeadingPadding: float
            imageBottomPadding: float
            imageTrailingPadding: float
            def __init__(self, latexExpression: _Optional[str] = ..., URL: _Optional[str] = ..., width: _Optional[float] = ..., height: _Optional[float] = ..., fontHeight: _Optional[float] = ..., imageTopPadding: _Optional[float] = ..., imageLeadingPadding: _Optional[float] = ..., imageBottomPadding: _Optional[float] = ..., imageTrailingPadding: _Optional[float] = ...) -> None: ...
        TEXT_FIELD_NUMBER: _ClassVar[int]
        EXPRESSIONS_FIELD_NUMBER: _ClassVar[int]
        text: str
        expressions: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseLatexMetadata.AIRichResponseLatexExpression]
        def __init__(self, text: _Optional[str] = ..., expressions: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseLatexMetadata.AIRichResponseLatexExpression, _Mapping]]] = ...) -> None: ...
    class AIRichResponseUnifiedResponse(_message.Message):
        __slots__ = ("data",)
        DATA_FIELD_NUMBER: _ClassVar[int]
        data: bytes
        def __init__(self, data: _Optional[bytes] = ...) -> None: ...
    class AIRichResponseTableMetadata(_message.Message):
        __slots__ = ("rows",)
        class AIRichResponseTableRow(_message.Message):
            __slots__ = ("items", "isHeading")
            ITEMS_FIELD_NUMBER: _ClassVar[int]
            ISHEADING_FIELD_NUMBER: _ClassVar[int]
            items: _containers.RepeatedScalarFieldContainer[str]
            isHeading: bool
            def __init__(self, items: _Optional[_Iterable[str]] = ..., isHeading: bool = ...) -> None: ...
        ROWS_FIELD_NUMBER: _ClassVar[int]
        rows: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseTableMetadata.AIRichResponseTableRow]
        def __init__(self, rows: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseTableMetadata.AIRichResponseTableRow, _Mapping]]] = ...) -> None: ...
    class AIRichResponseGridImageMetadata(_message.Message):
        __slots__ = ("gridImageURL", "imageURLs")
        GRIDIMAGEURL_FIELD_NUMBER: _ClassVar[int]
        IMAGEURLS_FIELD_NUMBER: _ClassVar[int]
        gridImageURL: AIRichResponseMessage.AIRichResponseImageURL
        imageURLs: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseImageURL]
        def __init__(self, gridImageURL: _Optional[_Union[AIRichResponseMessage.AIRichResponseImageURL, _Mapping]] = ..., imageURLs: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseImageURL, _Mapping]]] = ...) -> None: ...
    class AIRichResponseImageURL(_message.Message):
        __slots__ = ("imagePreviewURL", "imageHighResURL", "sourceURL")
        IMAGEPREVIEWURL_FIELD_NUMBER: _ClassVar[int]
        IMAGEHIGHRESURL_FIELD_NUMBER: _ClassVar[int]
        SOURCEURL_FIELD_NUMBER: _ClassVar[int]
        imagePreviewURL: str
        imageHighResURL: str
        sourceURL: str
        def __init__(self, imagePreviewURL: _Optional[str] = ..., imageHighResURL: _Optional[str] = ..., sourceURL: _Optional[str] = ...) -> None: ...
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    SUBMESSAGES_FIELD_NUMBER: _ClassVar[int]
    UNIFIEDRESPONSE_FIELD_NUMBER: _ClassVar[int]
    messageType: AIRichResponseMessage.AIRichResponseMessageType
    submessages: _containers.RepeatedCompositeFieldContainer[AIRichResponseMessage.AIRichResponseSubMessage]
    unifiedResponse: AIRichResponseMessage.AIRichResponseUnifiedResponse
    def __init__(self, messageType: _Optional[_Union[AIRichResponseMessage.AIRichResponseMessageType, str]] = ..., submessages: _Optional[_Iterable[_Union[AIRichResponseMessage.AIRichResponseSubMessage, _Mapping]]] = ..., unifiedResponse: _Optional[_Union[AIRichResponseMessage.AIRichResponseUnifiedResponse, _Mapping]] = ...) -> None: ...

class BotPromotionMessageMetadata(_message.Message):
    __slots__ = ("promotionType", "buttonTitle")
    class BotPromotionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_TYPE: _ClassVar[BotPromotionMessageMetadata.BotPromotionType]
        C50: _ClassVar[BotPromotionMessageMetadata.BotPromotionType]
    UNKNOWN_TYPE: BotPromotionMessageMetadata.BotPromotionType
    C50: BotPromotionMessageMetadata.BotPromotionType
    PROMOTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    BUTTONTITLE_FIELD_NUMBER: _ClassVar[int]
    promotionType: BotPromotionMessageMetadata.BotPromotionType
    buttonTitle: str
    def __init__(self, promotionType: _Optional[_Union[BotPromotionMessageMetadata.BotPromotionType, str]] = ..., buttonTitle: _Optional[str] = ...) -> None: ...

class BotMediaMetadata(_message.Message):
    __slots__ = ("fileSHA256", "mediaKey", "fileEncSHA256", "directPath", "mediaKeyTimestamp", "mimetype", "orientationType")
    class OrientationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CENTER: _ClassVar[BotMediaMetadata.OrientationType]
        LEFT: _ClassVar[BotMediaMetadata.OrientationType]
        RIGHT: _ClassVar[BotMediaMetadata.OrientationType]
    CENTER: BotMediaMetadata.OrientationType
    LEFT: BotMediaMetadata.OrientationType
    RIGHT: BotMediaMetadata.OrientationType
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    ORIENTATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    fileSHA256: str
    mediaKey: str
    fileEncSHA256: str
    directPath: str
    mediaKeyTimestamp: int
    mimetype: str
    orientationType: BotMediaMetadata.OrientationType
    def __init__(self, fileSHA256: _Optional[str] = ..., mediaKey: _Optional[str] = ..., fileEncSHA256: _Optional[str] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., mimetype: _Optional[str] = ..., orientationType: _Optional[_Union[BotMediaMetadata.OrientationType, str]] = ...) -> None: ...

class BotReminderMetadata(_message.Message):
    __slots__ = ("requestMessageKey", "action", "name", "nextTriggerTimestamp", "frequency")
    class ReminderFrequency(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ONCE: _ClassVar[BotReminderMetadata.ReminderFrequency]
        DAILY: _ClassVar[BotReminderMetadata.ReminderFrequency]
        WEEKLY: _ClassVar[BotReminderMetadata.ReminderFrequency]
        BIWEEKLY: _ClassVar[BotReminderMetadata.ReminderFrequency]
        MONTHLY: _ClassVar[BotReminderMetadata.ReminderFrequency]
    ONCE: BotReminderMetadata.ReminderFrequency
    DAILY: BotReminderMetadata.ReminderFrequency
    WEEKLY: BotReminderMetadata.ReminderFrequency
    BIWEEKLY: BotReminderMetadata.ReminderFrequency
    MONTHLY: BotReminderMetadata.ReminderFrequency
    class ReminderAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NOTIFY: _ClassVar[BotReminderMetadata.ReminderAction]
        CREATE: _ClassVar[BotReminderMetadata.ReminderAction]
        DELETE: _ClassVar[BotReminderMetadata.ReminderAction]
        UPDATE: _ClassVar[BotReminderMetadata.ReminderAction]
    NOTIFY: BotReminderMetadata.ReminderAction
    CREATE: BotReminderMetadata.ReminderAction
    DELETE: BotReminderMetadata.ReminderAction
    UPDATE: BotReminderMetadata.ReminderAction
    REQUESTMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NEXTTRIGGERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    FREQUENCY_FIELD_NUMBER: _ClassVar[int]
    requestMessageKey: _WACommon_pb2.MessageKey
    action: BotReminderMetadata.ReminderAction
    name: str
    nextTriggerTimestamp: int
    frequency: BotReminderMetadata.ReminderFrequency
    def __init__(self, requestMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., action: _Optional[_Union[BotReminderMetadata.ReminderAction, str]] = ..., name: _Optional[str] = ..., nextTriggerTimestamp: _Optional[int] = ..., frequency: _Optional[_Union[BotReminderMetadata.ReminderFrequency, str]] = ...) -> None: ...

class BotModelMetadata(_message.Message):
    __slots__ = ("modelType", "premiumModelStatus")
    class PremiumModelStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_STATUS: _ClassVar[BotModelMetadata.PremiumModelStatus]
        AVAILABLE: _ClassVar[BotModelMetadata.PremiumModelStatus]
        QUOTA_EXCEED_LIMIT: _ClassVar[BotModelMetadata.PremiumModelStatus]
    UNKNOWN_STATUS: BotModelMetadata.PremiumModelStatus
    AVAILABLE: BotModelMetadata.PremiumModelStatus
    QUOTA_EXCEED_LIMIT: BotModelMetadata.PremiumModelStatus
    class ModelType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_TYPE: _ClassVar[BotModelMetadata.ModelType]
        LLAMA_PROD: _ClassVar[BotModelMetadata.ModelType]
        LLAMA_PROD_PREMIUM: _ClassVar[BotModelMetadata.ModelType]
    UNKNOWN_TYPE: BotModelMetadata.ModelType
    LLAMA_PROD: BotModelMetadata.ModelType
    LLAMA_PROD_PREMIUM: BotModelMetadata.ModelType
    MODELTYPE_FIELD_NUMBER: _ClassVar[int]
    PREMIUMMODELSTATUS_FIELD_NUMBER: _ClassVar[int]
    modelType: BotModelMetadata.ModelType
    premiumModelStatus: BotModelMetadata.PremiumModelStatus
    def __init__(self, modelType: _Optional[_Union[BotModelMetadata.ModelType, str]] = ..., premiumModelStatus: _Optional[_Union[BotModelMetadata.PremiumModelStatus, str]] = ...) -> None: ...

class BotProgressIndicatorMetadata(_message.Message):
    __slots__ = ("progressDescription", "stepsMetadata")
    class BotPlanningStepMetadata(_message.Message):
        __slots__ = ("statusTitle", "statusBody", "sourcesMetadata", "status", "isReasoning", "isEnhancedSearch", "sections")
        class BotSearchSourceProvider(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_PROVIDER: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider]
            OTHER: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider]
            GOOGLE: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider]
            BING: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider]
        UNKNOWN_PROVIDER: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider
        OTHER: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider
        GOOGLE: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider
        BING: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider
        class PlanningStepStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus]
            PLANNED: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus]
            EXECUTING: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus]
            FINISHED: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus]
        UNKNOWN: BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus
        PLANNED: BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus
        EXECUTING: BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus
        FINISHED: BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus
        class BotPlanningSearchSourcesMetadata(_message.Message):
            __slots__ = ("sourceTitle", "provider", "sourceURL")
            class BotPlanningSearchSourceProvider(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                UNKNOWN: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider]
                OTHER: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider]
                GOOGLE: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider]
                BING: _ClassVar[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider]
            UNKNOWN: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider
            OTHER: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider
            GOOGLE: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider
            BING: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider
            SOURCETITLE_FIELD_NUMBER: _ClassVar[int]
            PROVIDER_FIELD_NUMBER: _ClassVar[int]
            SOURCEURL_FIELD_NUMBER: _ClassVar[int]
            sourceTitle: str
            provider: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider
            sourceURL: str
            def __init__(self, sourceTitle: _Optional[str] = ..., provider: _Optional[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata.BotPlanningSearchSourceProvider, str]] = ..., sourceURL: _Optional[str] = ...) -> None: ...
        class BotPlanningStepSectionMetadata(_message.Message):
            __slots__ = ("sectionTitle", "sectionBody", "sourcesMetadata")
            SECTIONTITLE_FIELD_NUMBER: _ClassVar[int]
            SECTIONBODY_FIELD_NUMBER: _ClassVar[int]
            SOURCESMETADATA_FIELD_NUMBER: _ClassVar[int]
            sectionTitle: str
            sectionBody: str
            sourcesMetadata: _containers.RepeatedCompositeFieldContainer[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourceMetadata]
            def __init__(self, sectionTitle: _Optional[str] = ..., sectionBody: _Optional[str] = ..., sourcesMetadata: _Optional[_Iterable[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourceMetadata, _Mapping]]] = ...) -> None: ...
        class BotPlanningSearchSourceMetadata(_message.Message):
            __slots__ = ("title", "provider", "sourceURL", "favIconURL")
            TITLE_FIELD_NUMBER: _ClassVar[int]
            PROVIDER_FIELD_NUMBER: _ClassVar[int]
            SOURCEURL_FIELD_NUMBER: _ClassVar[int]
            FAVICONURL_FIELD_NUMBER: _ClassVar[int]
            title: str
            provider: BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider
            sourceURL: str
            favIconURL: str
            def __init__(self, title: _Optional[str] = ..., provider: _Optional[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotSearchSourceProvider, str]] = ..., sourceURL: _Optional[str] = ..., favIconURL: _Optional[str] = ...) -> None: ...
        STATUSTITLE_FIELD_NUMBER: _ClassVar[int]
        STATUSBODY_FIELD_NUMBER: _ClassVar[int]
        SOURCESMETADATA_FIELD_NUMBER: _ClassVar[int]
        STATUS_FIELD_NUMBER: _ClassVar[int]
        ISREASONING_FIELD_NUMBER: _ClassVar[int]
        ISENHANCEDSEARCH_FIELD_NUMBER: _ClassVar[int]
        SECTIONS_FIELD_NUMBER: _ClassVar[int]
        statusTitle: str
        statusBody: str
        sourcesMetadata: _containers.RepeatedCompositeFieldContainer[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata]
        status: BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus
        isReasoning: bool
        isEnhancedSearch: bool
        sections: _containers.RepeatedCompositeFieldContainer[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningStepSectionMetadata]
        def __init__(self, statusTitle: _Optional[str] = ..., statusBody: _Optional[str] = ..., sourcesMetadata: _Optional[_Iterable[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningSearchSourcesMetadata, _Mapping]]] = ..., status: _Optional[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.PlanningStepStatus, str]] = ..., isReasoning: bool = ..., isEnhancedSearch: bool = ..., sections: _Optional[_Iterable[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata.BotPlanningStepSectionMetadata, _Mapping]]] = ...) -> None: ...
    PROGRESSDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    STEPSMETADATA_FIELD_NUMBER: _ClassVar[int]
    progressDescription: str
    stepsMetadata: _containers.RepeatedCompositeFieldContainer[BotProgressIndicatorMetadata.BotPlanningStepMetadata]
    def __init__(self, progressDescription: _Optional[str] = ..., stepsMetadata: _Optional[_Iterable[_Union[BotProgressIndicatorMetadata.BotPlanningStepMetadata, _Mapping]]] = ...) -> None: ...

class BotCapabilityMetadata(_message.Message):
    __slots__ = ("capabilities",)
    class BotCapabilityType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        PROGRESS_INDICATOR: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_HEADING: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_NESTED_LIST: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        AI_MEMORY: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_THREAD_SURFING: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_TABLE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_CODE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_STRUCTURED_RESPONSE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_INLINE_IMAGE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_CONTROL: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_1: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_2: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_3: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_4: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_5: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_6: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_7: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_8: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_9: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        WA_IG_1P_PLUGIN_RANKING_UPDATE_10: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_SUB_HEADING: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_GRID_IMAGE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        AI_STUDIO_UGC_MEMORY: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_LATEX: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_MAPS: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_INLINE_REELS: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        AGENTIC_PLANNING: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        ACCOUNT_LINKING: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        STREAMING_DISAGGREGATION: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_GRID_IMAGE_3P: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_LATEX_INLINE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        QUERY_PLAN: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        PROACTIVE_MESSAGE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        RICH_RESPONSE_UNIFIED_RESPONSE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
        PROMOTION_MESSAGE: _ClassVar[BotCapabilityMetadata.BotCapabilityType]
    UNKNOWN: BotCapabilityMetadata.BotCapabilityType
    PROGRESS_INDICATOR: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_HEADING: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_NESTED_LIST: BotCapabilityMetadata.BotCapabilityType
    AI_MEMORY: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_THREAD_SURFING: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_TABLE: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_CODE: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_STRUCTURED_RESPONSE: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_INLINE_IMAGE: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_CONTROL: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_1: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_2: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_3: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_4: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_5: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_6: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_7: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_8: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_9: BotCapabilityMetadata.BotCapabilityType
    WA_IG_1P_PLUGIN_RANKING_UPDATE_10: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_SUB_HEADING: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_GRID_IMAGE: BotCapabilityMetadata.BotCapabilityType
    AI_STUDIO_UGC_MEMORY: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_LATEX: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_MAPS: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_INLINE_REELS: BotCapabilityMetadata.BotCapabilityType
    AGENTIC_PLANNING: BotCapabilityMetadata.BotCapabilityType
    ACCOUNT_LINKING: BotCapabilityMetadata.BotCapabilityType
    STREAMING_DISAGGREGATION: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_GRID_IMAGE_3P: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_LATEX_INLINE: BotCapabilityMetadata.BotCapabilityType
    QUERY_PLAN: BotCapabilityMetadata.BotCapabilityType
    PROACTIVE_MESSAGE: BotCapabilityMetadata.BotCapabilityType
    RICH_RESPONSE_UNIFIED_RESPONSE: BotCapabilityMetadata.BotCapabilityType
    PROMOTION_MESSAGE: BotCapabilityMetadata.BotCapabilityType
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    capabilities: _containers.RepeatedScalarFieldContainer[BotCapabilityMetadata.BotCapabilityType]
    def __init__(self, capabilities: _Optional[_Iterable[_Union[BotCapabilityMetadata.BotCapabilityType, str]]] = ...) -> None: ...

class BotModeSelectionMetadata(_message.Message):
    __slots__ = ("mode",)
    class BotUserSelectionMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_MODE: _ClassVar[BotModeSelectionMetadata.BotUserSelectionMode]
        REASONING_MODE: _ClassVar[BotModeSelectionMetadata.BotUserSelectionMode]
    UNKNOWN_MODE: BotModeSelectionMetadata.BotUserSelectionMode
    REASONING_MODE: BotModeSelectionMetadata.BotUserSelectionMode
    MODE_FIELD_NUMBER: _ClassVar[int]
    mode: _containers.RepeatedScalarFieldContainer[BotModeSelectionMetadata.BotUserSelectionMode]
    def __init__(self, mode: _Optional[_Iterable[_Union[BotModeSelectionMetadata.BotUserSelectionMode, str]]] = ...) -> None: ...

class BotQuotaMetadata(_message.Message):
    __slots__ = ("botFeatureQuotaMetadata",)
    class BotFeatureQuotaMetadata(_message.Message):
        __slots__ = ("featureType", "remainingQuota", "expirationTimestamp")
        class BotFeatureType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_FEATURE: _ClassVar[BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType]
            REASONING_FEATURE: _ClassVar[BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType]
        UNKNOWN_FEATURE: BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType
        REASONING_FEATURE: BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType
        FEATURETYPE_FIELD_NUMBER: _ClassVar[int]
        REMAININGQUOTA_FIELD_NUMBER: _ClassVar[int]
        EXPIRATIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        featureType: BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType
        remainingQuota: int
        expirationTimestamp: int
        def __init__(self, featureType: _Optional[_Union[BotQuotaMetadata.BotFeatureQuotaMetadata.BotFeatureType, str]] = ..., remainingQuota: _Optional[int] = ..., expirationTimestamp: _Optional[int] = ...) -> None: ...
    BOTFEATUREQUOTAMETADATA_FIELD_NUMBER: _ClassVar[int]
    botFeatureQuotaMetadata: _containers.RepeatedCompositeFieldContainer[BotQuotaMetadata.BotFeatureQuotaMetadata]
    def __init__(self, botFeatureQuotaMetadata: _Optional[_Iterable[_Union[BotQuotaMetadata.BotFeatureQuotaMetadata, _Mapping]]] = ...) -> None: ...

class BotImagineMetadata(_message.Message):
    __slots__ = ("imagineType",)
    class ImagineType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[BotImagineMetadata.ImagineType]
        IMAGINE: _ClassVar[BotImagineMetadata.ImagineType]
        MEMU: _ClassVar[BotImagineMetadata.ImagineType]
        FLASH: _ClassVar[BotImagineMetadata.ImagineType]
        EDIT: _ClassVar[BotImagineMetadata.ImagineType]
    UNKNOWN: BotImagineMetadata.ImagineType
    IMAGINE: BotImagineMetadata.ImagineType
    MEMU: BotImagineMetadata.ImagineType
    FLASH: BotImagineMetadata.ImagineType
    EDIT: BotImagineMetadata.ImagineType
    IMAGINETYPE_FIELD_NUMBER: _ClassVar[int]
    imagineType: BotImagineMetadata.ImagineType
    def __init__(self, imagineType: _Optional[_Union[BotImagineMetadata.ImagineType, str]] = ...) -> None: ...

class BotSourcesMetadata(_message.Message):
    __slots__ = ("sources",)
    class BotSourceItem(_message.Message):
        __slots__ = ("provider", "thumbnailCDNURL", "sourceProviderURL", "sourceQuery", "faviconCDNURL", "citationNumber")
        class SourceProvider(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[BotSourcesMetadata.BotSourceItem.SourceProvider]
            BING: _ClassVar[BotSourcesMetadata.BotSourceItem.SourceProvider]
            GOOGLE: _ClassVar[BotSourcesMetadata.BotSourceItem.SourceProvider]
            SUPPORT: _ClassVar[BotSourcesMetadata.BotSourceItem.SourceProvider]
        UNKNOWN: BotSourcesMetadata.BotSourceItem.SourceProvider
        BING: BotSourcesMetadata.BotSourceItem.SourceProvider
        GOOGLE: BotSourcesMetadata.BotSourceItem.SourceProvider
        SUPPORT: BotSourcesMetadata.BotSourceItem.SourceProvider
        PROVIDER_FIELD_NUMBER: _ClassVar[int]
        THUMBNAILCDNURL_FIELD_NUMBER: _ClassVar[int]
        SOURCEPROVIDERURL_FIELD_NUMBER: _ClassVar[int]
        SOURCEQUERY_FIELD_NUMBER: _ClassVar[int]
        FAVICONCDNURL_FIELD_NUMBER: _ClassVar[int]
        CITATIONNUMBER_FIELD_NUMBER: _ClassVar[int]
        provider: BotSourcesMetadata.BotSourceItem.SourceProvider
        thumbnailCDNURL: str
        sourceProviderURL: str
        sourceQuery: str
        faviconCDNURL: str
        citationNumber: int
        def __init__(self, provider: _Optional[_Union[BotSourcesMetadata.BotSourceItem.SourceProvider, str]] = ..., thumbnailCDNURL: _Optional[str] = ..., sourceProviderURL: _Optional[str] = ..., sourceQuery: _Optional[str] = ..., faviconCDNURL: _Optional[str] = ..., citationNumber: _Optional[int] = ...) -> None: ...
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    sources: _containers.RepeatedCompositeFieldContainer[BotSourcesMetadata.BotSourceItem]
    def __init__(self, sources: _Optional[_Iterable[_Union[BotSourcesMetadata.BotSourceItem, _Mapping]]] = ...) -> None: ...

class MessageAssociation(_message.Message):
    __slots__ = ("associationType", "parentMessageKey", "messageIndex")
    class AssociationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[MessageAssociation.AssociationType]
        MEDIA_ALBUM: _ClassVar[MessageAssociation.AssociationType]
        BOT_PLUGIN: _ClassVar[MessageAssociation.AssociationType]
        EVENT_COVER_IMAGE: _ClassVar[MessageAssociation.AssociationType]
        STATUS_POLL: _ClassVar[MessageAssociation.AssociationType]
        HD_VIDEO_DUAL_UPLOAD: _ClassVar[MessageAssociation.AssociationType]
        STATUS_EXTERNAL_RESHARE: _ClassVar[MessageAssociation.AssociationType]
        MEDIA_POLL: _ClassVar[MessageAssociation.AssociationType]
        STATUS_ADD_YOURS: _ClassVar[MessageAssociation.AssociationType]
        STATUS_NOTIFICATION: _ClassVar[MessageAssociation.AssociationType]
        HD_IMAGE_DUAL_UPLOAD: _ClassVar[MessageAssociation.AssociationType]
        STICKER_ANNOTATION: _ClassVar[MessageAssociation.AssociationType]
        MOTION_PHOTO: _ClassVar[MessageAssociation.AssociationType]
        STATUS_LINK_ACTION: _ClassVar[MessageAssociation.AssociationType]
        VIEW_ALL_REPLIES: _ClassVar[MessageAssociation.AssociationType]
    UNKNOWN: MessageAssociation.AssociationType
    MEDIA_ALBUM: MessageAssociation.AssociationType
    BOT_PLUGIN: MessageAssociation.AssociationType
    EVENT_COVER_IMAGE: MessageAssociation.AssociationType
    STATUS_POLL: MessageAssociation.AssociationType
    HD_VIDEO_DUAL_UPLOAD: MessageAssociation.AssociationType
    STATUS_EXTERNAL_RESHARE: MessageAssociation.AssociationType
    MEDIA_POLL: MessageAssociation.AssociationType
    STATUS_ADD_YOURS: MessageAssociation.AssociationType
    STATUS_NOTIFICATION: MessageAssociation.AssociationType
    HD_IMAGE_DUAL_UPLOAD: MessageAssociation.AssociationType
    STICKER_ANNOTATION: MessageAssociation.AssociationType
    MOTION_PHOTO: MessageAssociation.AssociationType
    STATUS_LINK_ACTION: MessageAssociation.AssociationType
    VIEW_ALL_REPLIES: MessageAssociation.AssociationType
    ASSOCIATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    PARENTMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGEINDEX_FIELD_NUMBER: _ClassVar[int]
    associationType: MessageAssociation.AssociationType
    parentMessageKey: _WACommon_pb2.MessageKey
    messageIndex: int
    def __init__(self, associationType: _Optional[_Union[MessageAssociation.AssociationType, str]] = ..., parentMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., messageIndex: _Optional[int] = ...) -> None: ...

class MessageContextInfo(_message.Message):
    __slots__ = ("deviceListMetadata", "deviceListMetadataVersion", "messageSecret", "paddingBytes", "messageAddOnDurationInSecs", "botMessageSecret", "botMetadata", "reportingTokenVersion", "messageAddOnExpiryType", "messageAssociation", "capiCreatedGroup", "supportPayload", "limitSharing", "limitSharingV2")
    class MessageAddonExpiryType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        STATIC: _ClassVar[MessageContextInfo.MessageAddonExpiryType]
        DEPENDENT_ON_PARENT: _ClassVar[MessageContextInfo.MessageAddonExpiryType]
    STATIC: MessageContextInfo.MessageAddonExpiryType
    DEPENDENT_ON_PARENT: MessageContextInfo.MessageAddonExpiryType
    DEVICELISTMETADATA_FIELD_NUMBER: _ClassVar[int]
    DEVICELISTMETADATAVERSION_FIELD_NUMBER: _ClassVar[int]
    MESSAGESECRET_FIELD_NUMBER: _ClassVar[int]
    PADDINGBYTES_FIELD_NUMBER: _ClassVar[int]
    MESSAGEADDONDURATIONINSECS_FIELD_NUMBER: _ClassVar[int]
    BOTMESSAGESECRET_FIELD_NUMBER: _ClassVar[int]
    BOTMETADATA_FIELD_NUMBER: _ClassVar[int]
    REPORTINGTOKENVERSION_FIELD_NUMBER: _ClassVar[int]
    MESSAGEADDONEXPIRYTYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEASSOCIATION_FIELD_NUMBER: _ClassVar[int]
    CAPICREATEDGROUP_FIELD_NUMBER: _ClassVar[int]
    SUPPORTPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARING_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGV2_FIELD_NUMBER: _ClassVar[int]
    deviceListMetadata: DeviceListMetadata
    deviceListMetadataVersion: int
    messageSecret: bytes
    paddingBytes: bytes
    messageAddOnDurationInSecs: int
    botMessageSecret: bytes
    botMetadata: BotMetadata
    reportingTokenVersion: int
    messageAddOnExpiryType: MessageContextInfo.MessageAddonExpiryType
    messageAssociation: MessageAssociation
    capiCreatedGroup: bool
    supportPayload: str
    limitSharing: _WACommon_pb2.LimitSharing
    limitSharingV2: _WACommon_pb2.LimitSharing
    def __init__(self, deviceListMetadata: _Optional[_Union[DeviceListMetadata, _Mapping]] = ..., deviceListMetadataVersion: _Optional[int] = ..., messageSecret: _Optional[bytes] = ..., paddingBytes: _Optional[bytes] = ..., messageAddOnDurationInSecs: _Optional[int] = ..., botMessageSecret: _Optional[bytes] = ..., botMetadata: _Optional[_Union[BotMetadata, _Mapping]] = ..., reportingTokenVersion: _Optional[int] = ..., messageAddOnExpiryType: _Optional[_Union[MessageContextInfo.MessageAddonExpiryType, str]] = ..., messageAssociation: _Optional[_Union[MessageAssociation, _Mapping]] = ..., capiCreatedGroup: bool = ..., supportPayload: _Optional[str] = ..., limitSharing: _Optional[_Union[_WACommon_pb2.LimitSharing, _Mapping]] = ..., limitSharingV2: _Optional[_Union[_WACommon_pb2.LimitSharing, _Mapping]] = ...) -> None: ...

class InteractiveAnnotation(_message.Message):
    __slots__ = ("location", "newsletter", "embeddedAction", "tapAction", "polygonVertices", "shouldSkipConfirmation", "embeddedContent", "statusLinkType")
    class StatusLinkType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        RASTERIZED_LINK_PREVIEW: _ClassVar[InteractiveAnnotation.StatusLinkType]
        RASTERIZED_LINK_TRUNCATED: _ClassVar[InteractiveAnnotation.StatusLinkType]
        RASTERIZED_LINK_FULL_URL: _ClassVar[InteractiveAnnotation.StatusLinkType]
    RASTERIZED_LINK_PREVIEW: InteractiveAnnotation.StatusLinkType
    RASTERIZED_LINK_TRUNCATED: InteractiveAnnotation.StatusLinkType
    RASTERIZED_LINK_FULL_URL: InteractiveAnnotation.StatusLinkType
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    NEWSLETTER_FIELD_NUMBER: _ClassVar[int]
    EMBEDDEDACTION_FIELD_NUMBER: _ClassVar[int]
    TAPACTION_FIELD_NUMBER: _ClassVar[int]
    POLYGONVERTICES_FIELD_NUMBER: _ClassVar[int]
    SHOULDSKIPCONFIRMATION_FIELD_NUMBER: _ClassVar[int]
    EMBEDDEDCONTENT_FIELD_NUMBER: _ClassVar[int]
    STATUSLINKTYPE_FIELD_NUMBER: _ClassVar[int]
    location: Location
    newsletter: ContextInfo.ForwardedNewsletterMessageInfo
    embeddedAction: bool
    tapAction: TapLinkAction
    polygonVertices: _containers.RepeatedCompositeFieldContainer[Point]
    shouldSkipConfirmation: bool
    embeddedContent: EmbeddedContent
    statusLinkType: InteractiveAnnotation.StatusLinkType
    def __init__(self, location: _Optional[_Union[Location, _Mapping]] = ..., newsletter: _Optional[_Union[ContextInfo.ForwardedNewsletterMessageInfo, _Mapping]] = ..., embeddedAction: bool = ..., tapAction: _Optional[_Union[TapLinkAction, _Mapping]] = ..., polygonVertices: _Optional[_Iterable[_Union[Point, _Mapping]]] = ..., shouldSkipConfirmation: bool = ..., embeddedContent: _Optional[_Union[EmbeddedContent, _Mapping]] = ..., statusLinkType: _Optional[_Union[InteractiveAnnotation.StatusLinkType, str]] = ...) -> None: ...

class HydratedTemplateButton(_message.Message):
    __slots__ = ("quickReplyButton", "urlButton", "callButton", "index")
    class HydratedURLButton(_message.Message):
        __slots__ = ("displayText", "URL", "consentedUsersURL", "webviewPresentation")
        class WebviewPresentationType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            FULL: _ClassVar[HydratedTemplateButton.HydratedURLButton.WebviewPresentationType]
            TALL: _ClassVar[HydratedTemplateButton.HydratedURLButton.WebviewPresentationType]
            COMPACT: _ClassVar[HydratedTemplateButton.HydratedURLButton.WebviewPresentationType]
        FULL: HydratedTemplateButton.HydratedURLButton.WebviewPresentationType
        TALL: HydratedTemplateButton.HydratedURLButton.WebviewPresentationType
        COMPACT: HydratedTemplateButton.HydratedURLButton.WebviewPresentationType
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        URL_FIELD_NUMBER: _ClassVar[int]
        CONSENTEDUSERSURL_FIELD_NUMBER: _ClassVar[int]
        WEBVIEWPRESENTATION_FIELD_NUMBER: _ClassVar[int]
        displayText: str
        URL: str
        consentedUsersURL: str
        webviewPresentation: HydratedTemplateButton.HydratedURLButton.WebviewPresentationType
        def __init__(self, displayText: _Optional[str] = ..., URL: _Optional[str] = ..., consentedUsersURL: _Optional[str] = ..., webviewPresentation: _Optional[_Union[HydratedTemplateButton.HydratedURLButton.WebviewPresentationType, str]] = ...) -> None: ...
    class HydratedCallButton(_message.Message):
        __slots__ = ("displayText", "phoneNumber")
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
        displayText: str
        phoneNumber: str
        def __init__(self, displayText: _Optional[str] = ..., phoneNumber: _Optional[str] = ...) -> None: ...
    class HydratedQuickReplyButton(_message.Message):
        __slots__ = ("displayText", "ID")
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        displayText: str
        ID: str
        def __init__(self, displayText: _Optional[str] = ..., ID: _Optional[str] = ...) -> None: ...
    QUICKREPLYBUTTON_FIELD_NUMBER: _ClassVar[int]
    URLBUTTON_FIELD_NUMBER: _ClassVar[int]
    CALLBUTTON_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    quickReplyButton: HydratedTemplateButton.HydratedQuickReplyButton
    urlButton: HydratedTemplateButton.HydratedURLButton
    callButton: HydratedTemplateButton.HydratedCallButton
    index: int
    def __init__(self, quickReplyButton: _Optional[_Union[HydratedTemplateButton.HydratedQuickReplyButton, _Mapping]] = ..., urlButton: _Optional[_Union[HydratedTemplateButton.HydratedURLButton, _Mapping]] = ..., callButton: _Optional[_Union[HydratedTemplateButton.HydratedCallButton, _Mapping]] = ..., index: _Optional[int] = ...) -> None: ...

class PaymentBackground(_message.Message):
    __slots__ = ("ID", "fileLength", "width", "height", "mimetype", "placeholderArgb", "textArgb", "subtextArgb", "mediaData", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[PaymentBackground.Type]
        DEFAULT: _ClassVar[PaymentBackground.Type]
    UNKNOWN: PaymentBackground.Type
    DEFAULT: PaymentBackground.Type
    class MediaData(_message.Message):
        __slots__ = ("mediaKey", "mediaKeyTimestamp", "fileSHA256", "fileEncSHA256", "directPath")
        MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
        MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        FILESHA256_FIELD_NUMBER: _ClassVar[int]
        FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
        DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
        mediaKey: bytes
        mediaKeyTimestamp: int
        fileSHA256: bytes
        fileEncSHA256: bytes
        directPath: str
        def __init__(self, mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDERARGB_FIELD_NUMBER: _ClassVar[int]
    TEXTARGB_FIELD_NUMBER: _ClassVar[int]
    SUBTEXTARGB_FIELD_NUMBER: _ClassVar[int]
    MEDIADATA_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID: str
    fileLength: int
    width: int
    height: int
    mimetype: str
    placeholderArgb: int
    textArgb: int
    subtextArgb: int
    mediaData: PaymentBackground.MediaData
    type: PaymentBackground.Type
    def __init__(self, ID: _Optional[str] = ..., fileLength: _Optional[int] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., mimetype: _Optional[str] = ..., placeholderArgb: _Optional[int] = ..., textArgb: _Optional[int] = ..., subtextArgb: _Optional[int] = ..., mediaData: _Optional[_Union[PaymentBackground.MediaData, _Mapping]] = ..., type: _Optional[_Union[PaymentBackground.Type, str]] = ...) -> None: ...

class DisappearingMode(_message.Message):
    __slots__ = ("initiator", "trigger", "initiatorDeviceJID", "initiatedByMe")
    class Trigger(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[DisappearingMode.Trigger]
        CHAT_SETTING: _ClassVar[DisappearingMode.Trigger]
        ACCOUNT_SETTING: _ClassVar[DisappearingMode.Trigger]
        BULK_CHANGE: _ClassVar[DisappearingMode.Trigger]
        BIZ_SUPPORTS_FB_HOSTING: _ClassVar[DisappearingMode.Trigger]
        UNKNOWN_GROUPS: _ClassVar[DisappearingMode.Trigger]
    UNKNOWN: DisappearingMode.Trigger
    CHAT_SETTING: DisappearingMode.Trigger
    ACCOUNT_SETTING: DisappearingMode.Trigger
    BULK_CHANGE: DisappearingMode.Trigger
    BIZ_SUPPORTS_FB_HOSTING: DisappearingMode.Trigger
    UNKNOWN_GROUPS: DisappearingMode.Trigger
    class Initiator(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CHANGED_IN_CHAT: _ClassVar[DisappearingMode.Initiator]
        INITIATED_BY_ME: _ClassVar[DisappearingMode.Initiator]
        INITIATED_BY_OTHER: _ClassVar[DisappearingMode.Initiator]
        BIZ_UPGRADE_FB_HOSTING: _ClassVar[DisappearingMode.Initiator]
    CHANGED_IN_CHAT: DisappearingMode.Initiator
    INITIATED_BY_ME: DisappearingMode.Initiator
    INITIATED_BY_OTHER: DisappearingMode.Initiator
    BIZ_UPGRADE_FB_HOSTING: DisappearingMode.Initiator
    INITIATOR_FIELD_NUMBER: _ClassVar[int]
    TRIGGER_FIELD_NUMBER: _ClassVar[int]
    INITIATORDEVICEJID_FIELD_NUMBER: _ClassVar[int]
    INITIATEDBYME_FIELD_NUMBER: _ClassVar[int]
    initiator: DisappearingMode.Initiator
    trigger: DisappearingMode.Trigger
    initiatorDeviceJID: str
    initiatedByMe: bool
    def __init__(self, initiator: _Optional[_Union[DisappearingMode.Initiator, str]] = ..., trigger: _Optional[_Union[DisappearingMode.Trigger, str]] = ..., initiatorDeviceJID: _Optional[str] = ..., initiatedByMe: bool = ...) -> None: ...

class ProcessedVideo(_message.Message):
    __slots__ = ("directPath", "fileSHA256", "height", "width", "fileLength", "bitrate", "quality", "capabilities")
    class VideoQuality(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNDEFINED: _ClassVar[ProcessedVideo.VideoQuality]
        LOW: _ClassVar[ProcessedVideo.VideoQuality]
        MID: _ClassVar[ProcessedVideo.VideoQuality]
        HIGH: _ClassVar[ProcessedVideo.VideoQuality]
    UNDEFINED: ProcessedVideo.VideoQuality
    LOW: ProcessedVideo.VideoQuality
    MID: ProcessedVideo.VideoQuality
    HIGH: ProcessedVideo.VideoQuality
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    BITRATE_FIELD_NUMBER: _ClassVar[int]
    QUALITY_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    directPath: str
    fileSHA256: bytes
    height: int
    width: int
    fileLength: int
    bitrate: int
    quality: ProcessedVideo.VideoQuality
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, directPath: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., fileLength: _Optional[int] = ..., bitrate: _Optional[int] = ..., quality: _Optional[_Union[ProcessedVideo.VideoQuality, str]] = ..., capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class Message(_message.Message):
    __slots__ = ("conversation", "senderKeyDistributionMessage", "imageMessage", "contactMessage", "locationMessage", "extendedTextMessage", "documentMessage", "audioMessage", "videoMessage", "call", "chat", "protocolMessage", "contactsArrayMessage", "highlyStructuredMessage", "fastRatchetKeySenderKeyDistributionMessage", "sendPaymentMessage", "liveLocationMessage", "requestPaymentMessage", "declinePaymentRequestMessage", "cancelPaymentRequestMessage", "templateMessage", "stickerMessage", "groupInviteMessage", "templateButtonReplyMessage", "productMessage", "deviceSentMessage", "messageContextInfo", "listMessage", "viewOnceMessage", "orderMessage", "listResponseMessage", "ephemeralMessage", "invoiceMessage", "buttonsMessage", "buttonsResponseMessage", "paymentInviteMessage", "interactiveMessage", "reactionMessage", "stickerSyncRmrMessage", "interactiveResponseMessage", "pollCreationMessage", "pollUpdateMessage", "keepInChatMessage", "documentWithCaptionMessage", "requestPhoneNumberMessage", "viewOnceMessageV2", "encReactionMessage", "editedMessage", "viewOnceMessageV2Extension", "pollCreationMessageV2", "scheduledCallCreationMessage", "groupMentionedMessage", "pinInChatMessage", "pollCreationMessageV3", "scheduledCallEditMessage", "ptvMessage", "botInvokeMessage", "callLogMesssage", "messageHistoryBundle", "encCommentMessage", "bcallMessage", "lottieStickerMessage", "eventMessage", "encEventResponseMessage", "commentMessage", "newsletterAdminInviteMessage", "placeholderMessage", "secretEncryptedMessage", "albumMessage", "eventCoverImage", "stickerPackMessage", "statusMentionMessage", "pollResultSnapshotMessage", "pollCreationOptionImageMessage", "associatedChildMessage", "groupStatusMentionMessage", "pollCreationMessageV4", "pollCreationMessageV5", "statusAddYours", "groupStatusMessage", "richResponseMessage", "statusNotificationMessage", "limitSharingMessage", "botTaskMessage", "questionMessage", "messageHistoryNotice")
    CONVERSATION_FIELD_NUMBER: _ClassVar[int]
    SENDERKEYDISTRIBUTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTACTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXTENDEDTEXTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUDIOMESSAGE_FIELD_NUMBER: _ClassVar[int]
    VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CALL_FIELD_NUMBER: _ClassVar[int]
    CHAT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOLMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTACTSARRAYMESSAGE_FIELD_NUMBER: _ClassVar[int]
    HIGHLYSTRUCTUREDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    FASTRATCHETKEYSENDERKEYDISTRIBUTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    SENDPAYMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LIVELOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REQUESTPAYMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    DECLINEPAYMENTREQUESTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CANCELPAYMENTREQUESTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    TEMPLATEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STICKERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    GROUPINVITEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    TEMPLATEBUTTONREPLYMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PRODUCTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    DEVICESENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    MESSAGECONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    LISTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    VIEWONCEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ORDERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LISTRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EPHEMERALMESSAGE_FIELD_NUMBER: _ClassVar[int]
    INVOICEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BUTTONSMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BUTTONSRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PAYMENTINVITEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REACTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STICKERSYNCRMRMESSAGE_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVERESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLUPDATEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    KEEPINCHATMESSAGE_FIELD_NUMBER: _ClassVar[int]
    DOCUMENTWITHCAPTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REQUESTPHONENUMBERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    VIEWONCEMESSAGEV2_FIELD_NUMBER: _ClassVar[int]
    ENCREACTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EDITEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    VIEWONCEMESSAGEV2EXTENSION_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONMESSAGEV2_FIELD_NUMBER: _ClassVar[int]
    SCHEDULEDCALLCREATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    GROUPMENTIONEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PININCHATMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONMESSAGEV3_FIELD_NUMBER: _ClassVar[int]
    SCHEDULEDCALLEDITMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PTVMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BOTINVOKEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CALLLOGMESSSAGE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEHISTORYBUNDLE_FIELD_NUMBER: _ClassVar[int]
    ENCCOMMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BCALLMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LOTTIESTICKERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EVENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ENCEVENTRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    COMMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    NEWSLETTERADMININVITEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    SECRETENCRYPTEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ALBUMMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EVENTCOVERIMAGE_FIELD_NUMBER: _ClassVar[int]
    STICKERPACKMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STATUSMENTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLRESULTSNAPSHOTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONOPTIONIMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ASSOCIATEDCHILDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    GROUPSTATUSMENTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONMESSAGEV4_FIELD_NUMBER: _ClassVar[int]
    POLLCREATIONMESSAGEV5_FIELD_NUMBER: _ClassVar[int]
    STATUSADDYOURS_FIELD_NUMBER: _ClassVar[int]
    GROUPSTATUSMESSAGE_FIELD_NUMBER: _ClassVar[int]
    RICHRESPONSEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STATUSNOTIFICATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGMESSAGE_FIELD_NUMBER: _ClassVar[int]
    BOTTASKMESSAGE_FIELD_NUMBER: _ClassVar[int]
    QUESTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEHISTORYNOTICE_FIELD_NUMBER: _ClassVar[int]
    conversation: str
    senderKeyDistributionMessage: SenderKeyDistributionMessage
    imageMessage: ImageMessage
    contactMessage: ContactMessage
    locationMessage: LocationMessage
    extendedTextMessage: ExtendedTextMessage
    documentMessage: DocumentMessage
    audioMessage: AudioMessage
    videoMessage: VideoMessage
    call: Call
    chat: Chat
    protocolMessage: ProtocolMessage
    contactsArrayMessage: ContactsArrayMessage
    highlyStructuredMessage: HighlyStructuredMessage
    fastRatchetKeySenderKeyDistributionMessage: SenderKeyDistributionMessage
    sendPaymentMessage: SendPaymentMessage
    liveLocationMessage: LiveLocationMessage
    requestPaymentMessage: RequestPaymentMessage
    declinePaymentRequestMessage: DeclinePaymentRequestMessage
    cancelPaymentRequestMessage: CancelPaymentRequestMessage
    templateMessage: TemplateMessage
    stickerMessage: StickerMessage
    groupInviteMessage: GroupInviteMessage
    templateButtonReplyMessage: TemplateButtonReplyMessage
    productMessage: ProductMessage
    deviceSentMessage: DeviceSentMessage
    messageContextInfo: MessageContextInfo
    listMessage: ListMessage
    viewOnceMessage: FutureProofMessage
    orderMessage: OrderMessage
    listResponseMessage: ListResponseMessage
    ephemeralMessage: FutureProofMessage
    invoiceMessage: InvoiceMessage
    buttonsMessage: ButtonsMessage
    buttonsResponseMessage: ButtonsResponseMessage
    paymentInviteMessage: PaymentInviteMessage
    interactiveMessage: InteractiveMessage
    reactionMessage: ReactionMessage
    stickerSyncRmrMessage: StickerSyncRMRMessage
    interactiveResponseMessage: InteractiveResponseMessage
    pollCreationMessage: PollCreationMessage
    pollUpdateMessage: PollUpdateMessage
    keepInChatMessage: KeepInChatMessage
    documentWithCaptionMessage: FutureProofMessage
    requestPhoneNumberMessage: RequestPhoneNumberMessage
    viewOnceMessageV2: FutureProofMessage
    encReactionMessage: EncReactionMessage
    editedMessage: FutureProofMessage
    viewOnceMessageV2Extension: FutureProofMessage
    pollCreationMessageV2: PollCreationMessage
    scheduledCallCreationMessage: ScheduledCallCreationMessage
    groupMentionedMessage: FutureProofMessage
    pinInChatMessage: PinInChatMessage
    pollCreationMessageV3: PollCreationMessage
    scheduledCallEditMessage: ScheduledCallEditMessage
    ptvMessage: VideoMessage
    botInvokeMessage: FutureProofMessage
    callLogMesssage: CallLogMessage
    messageHistoryBundle: MessageHistoryBundle
    encCommentMessage: EncCommentMessage
    bcallMessage: BCallMessage
    lottieStickerMessage: FutureProofMessage
    eventMessage: EventMessage
    encEventResponseMessage: EncEventResponseMessage
    commentMessage: CommentMessage
    newsletterAdminInviteMessage: NewsletterAdminInviteMessage
    placeholderMessage: PlaceholderMessage
    secretEncryptedMessage: SecretEncryptedMessage
    albumMessage: AlbumMessage
    eventCoverImage: FutureProofMessage
    stickerPackMessage: StickerPackMessage
    statusMentionMessage: FutureProofMessage
    pollResultSnapshotMessage: PollResultSnapshotMessage
    pollCreationOptionImageMessage: FutureProofMessage
    associatedChildMessage: FutureProofMessage
    groupStatusMentionMessage: FutureProofMessage
    pollCreationMessageV4: FutureProofMessage
    pollCreationMessageV5: FutureProofMessage
    statusAddYours: FutureProofMessage
    groupStatusMessage: FutureProofMessage
    richResponseMessage: AIRichResponseMessage
    statusNotificationMessage: StatusNotificationMessage
    limitSharingMessage: FutureProofMessage
    botTaskMessage: FutureProofMessage
    questionMessage: FutureProofMessage
    messageHistoryNotice: MessageHistoryNotice
    def __init__(self, conversation: _Optional[str] = ..., senderKeyDistributionMessage: _Optional[_Union[SenderKeyDistributionMessage, _Mapping]] = ..., imageMessage: _Optional[_Union[ImageMessage, _Mapping]] = ..., contactMessage: _Optional[_Union[ContactMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[LocationMessage, _Mapping]] = ..., extendedTextMessage: _Optional[_Union[ExtendedTextMessage, _Mapping]] = ..., documentMessage: _Optional[_Union[DocumentMessage, _Mapping]] = ..., audioMessage: _Optional[_Union[AudioMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., call: _Optional[_Union[Call, _Mapping]] = ..., chat: _Optional[_Union[Chat, _Mapping]] = ..., protocolMessage: _Optional[_Union[ProtocolMessage, _Mapping]] = ..., contactsArrayMessage: _Optional[_Union[ContactsArrayMessage, _Mapping]] = ..., highlyStructuredMessage: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., fastRatchetKeySenderKeyDistributionMessage: _Optional[_Union[SenderKeyDistributionMessage, _Mapping]] = ..., sendPaymentMessage: _Optional[_Union[SendPaymentMessage, _Mapping]] = ..., liveLocationMessage: _Optional[_Union[LiveLocationMessage, _Mapping]] = ..., requestPaymentMessage: _Optional[_Union[RequestPaymentMessage, _Mapping]] = ..., declinePaymentRequestMessage: _Optional[_Union[DeclinePaymentRequestMessage, _Mapping]] = ..., cancelPaymentRequestMessage: _Optional[_Union[CancelPaymentRequestMessage, _Mapping]] = ..., templateMessage: _Optional[_Union[TemplateMessage, _Mapping]] = ..., stickerMessage: _Optional[_Union[StickerMessage, _Mapping]] = ..., groupInviteMessage: _Optional[_Union[GroupInviteMessage, _Mapping]] = ..., templateButtonReplyMessage: _Optional[_Union[TemplateButtonReplyMessage, _Mapping]] = ..., productMessage: _Optional[_Union[ProductMessage, _Mapping]] = ..., deviceSentMessage: _Optional[_Union[DeviceSentMessage, _Mapping]] = ..., messageContextInfo: _Optional[_Union[MessageContextInfo, _Mapping]] = ..., listMessage: _Optional[_Union[ListMessage, _Mapping]] = ..., viewOnceMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., orderMessage: _Optional[_Union[OrderMessage, _Mapping]] = ..., listResponseMessage: _Optional[_Union[ListResponseMessage, _Mapping]] = ..., ephemeralMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., invoiceMessage: _Optional[_Union[InvoiceMessage, _Mapping]] = ..., buttonsMessage: _Optional[_Union[ButtonsMessage, _Mapping]] = ..., buttonsResponseMessage: _Optional[_Union[ButtonsResponseMessage, _Mapping]] = ..., paymentInviteMessage: _Optional[_Union[PaymentInviteMessage, _Mapping]] = ..., interactiveMessage: _Optional[_Union[InteractiveMessage, _Mapping]] = ..., reactionMessage: _Optional[_Union[ReactionMessage, _Mapping]] = ..., stickerSyncRmrMessage: _Optional[_Union[StickerSyncRMRMessage, _Mapping]] = ..., interactiveResponseMessage: _Optional[_Union[InteractiveResponseMessage, _Mapping]] = ..., pollCreationMessage: _Optional[_Union[PollCreationMessage, _Mapping]] = ..., pollUpdateMessage: _Optional[_Union[PollUpdateMessage, _Mapping]] = ..., keepInChatMessage: _Optional[_Union[KeepInChatMessage, _Mapping]] = ..., documentWithCaptionMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., requestPhoneNumberMessage: _Optional[_Union[RequestPhoneNumberMessage, _Mapping]] = ..., viewOnceMessageV2: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., encReactionMessage: _Optional[_Union[EncReactionMessage, _Mapping]] = ..., editedMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., viewOnceMessageV2Extension: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., pollCreationMessageV2: _Optional[_Union[PollCreationMessage, _Mapping]] = ..., scheduledCallCreationMessage: _Optional[_Union[ScheduledCallCreationMessage, _Mapping]] = ..., groupMentionedMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., pinInChatMessage: _Optional[_Union[PinInChatMessage, _Mapping]] = ..., pollCreationMessageV3: _Optional[_Union[PollCreationMessage, _Mapping]] = ..., scheduledCallEditMessage: _Optional[_Union[ScheduledCallEditMessage, _Mapping]] = ..., ptvMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., botInvokeMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., callLogMesssage: _Optional[_Union[CallLogMessage, _Mapping]] = ..., messageHistoryBundle: _Optional[_Union[MessageHistoryBundle, _Mapping]] = ..., encCommentMessage: _Optional[_Union[EncCommentMessage, _Mapping]] = ..., bcallMessage: _Optional[_Union[BCallMessage, _Mapping]] = ..., lottieStickerMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., eventMessage: _Optional[_Union[EventMessage, _Mapping]] = ..., encEventResponseMessage: _Optional[_Union[EncEventResponseMessage, _Mapping]] = ..., commentMessage: _Optional[_Union[CommentMessage, _Mapping]] = ..., newsletterAdminInviteMessage: _Optional[_Union[NewsletterAdminInviteMessage, _Mapping]] = ..., placeholderMessage: _Optional[_Union[PlaceholderMessage, _Mapping]] = ..., secretEncryptedMessage: _Optional[_Union[SecretEncryptedMessage, _Mapping]] = ..., albumMessage: _Optional[_Union[AlbumMessage, _Mapping]] = ..., eventCoverImage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., stickerPackMessage: _Optional[_Union[StickerPackMessage, _Mapping]] = ..., statusMentionMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., pollResultSnapshotMessage: _Optional[_Union[PollResultSnapshotMessage, _Mapping]] = ..., pollCreationOptionImageMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., associatedChildMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., groupStatusMentionMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., pollCreationMessageV4: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., pollCreationMessageV5: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., statusAddYours: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., groupStatusMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., richResponseMessage: _Optional[_Union[AIRichResponseMessage, _Mapping]] = ..., statusNotificationMessage: _Optional[_Union[StatusNotificationMessage, _Mapping]] = ..., limitSharingMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., botTaskMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., questionMessage: _Optional[_Union[FutureProofMessage, _Mapping]] = ..., messageHistoryNotice: _Optional[_Union[MessageHistoryNotice, _Mapping]] = ...) -> None: ...

class AlbumMessage(_message.Message):
    __slots__ = ("expectedImageCount", "expectedVideoCount", "contextInfo")
    EXPECTEDIMAGECOUNT_FIELD_NUMBER: _ClassVar[int]
    EXPECTEDVIDEOCOUNT_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    expectedImageCount: int
    expectedVideoCount: int
    contextInfo: ContextInfo
    def __init__(self, expectedImageCount: _Optional[int] = ..., expectedVideoCount: _Optional[int] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class MessageHistoryMetadata(_message.Message):
    __slots__ = ("historyReceivers", "firstMessageTimestamp", "messageCount")
    HISTORYRECEIVERS_FIELD_NUMBER: _ClassVar[int]
    FIRSTMESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    MESSAGECOUNT_FIELD_NUMBER: _ClassVar[int]
    historyReceivers: _containers.RepeatedScalarFieldContainer[str]
    firstMessageTimestamp: int
    messageCount: int
    def __init__(self, historyReceivers: _Optional[_Iterable[str]] = ..., firstMessageTimestamp: _Optional[int] = ..., messageCount: _Optional[int] = ...) -> None: ...

class MessageHistoryNotice(_message.Message):
    __slots__ = ("contextInfo", "messageHistoryMetadata")
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    MESSAGEHISTORYMETADATA_FIELD_NUMBER: _ClassVar[int]
    contextInfo: ContextInfo
    messageHistoryMetadata: MessageHistoryMetadata
    def __init__(self, contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., messageHistoryMetadata: _Optional[_Union[MessageHistoryMetadata, _Mapping]] = ...) -> None: ...

class MessageHistoryBundle(_message.Message):
    __slots__ = ("mimetype", "fileSHA256", "mediaKey", "fileEncSHA256", "directPath", "mediaKeyTimestamp", "contextInfo", "messageHistoryMetadata")
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    MESSAGEHISTORYMETADATA_FIELD_NUMBER: _ClassVar[int]
    mimetype: str
    fileSHA256: bytes
    mediaKey: bytes
    fileEncSHA256: bytes
    directPath: str
    mediaKeyTimestamp: int
    contextInfo: ContextInfo
    messageHistoryMetadata: MessageHistoryMetadata
    def __init__(self, mimetype: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., messageHistoryMetadata: _Optional[_Union[MessageHistoryMetadata, _Mapping]] = ...) -> None: ...

class EncEventResponseMessage(_message.Message):
    __slots__ = ("eventCreationMessageKey", "encPayload", "encIV")
    EVENTCREATIONMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    eventCreationMessageKey: _WACommon_pb2.MessageKey
    encPayload: bytes
    encIV: bytes
    def __init__(self, eventCreationMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ...) -> None: ...

class EventMessage(_message.Message):
    __slots__ = ("contextInfo", "isCanceled", "name", "description", "location", "joinLink", "startTime", "endTime", "extraGuestsAllowed", "isScheduleCall")
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    ISCANCELED_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    JOINLINK_FIELD_NUMBER: _ClassVar[int]
    STARTTIME_FIELD_NUMBER: _ClassVar[int]
    ENDTIME_FIELD_NUMBER: _ClassVar[int]
    EXTRAGUESTSALLOWED_FIELD_NUMBER: _ClassVar[int]
    ISSCHEDULECALL_FIELD_NUMBER: _ClassVar[int]
    contextInfo: ContextInfo
    isCanceled: bool
    name: str
    description: str
    location: LocationMessage
    joinLink: str
    startTime: int
    endTime: int
    extraGuestsAllowed: bool
    isScheduleCall: bool
    def __init__(self, contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., isCanceled: bool = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., location: _Optional[_Union[LocationMessage, _Mapping]] = ..., joinLink: _Optional[str] = ..., startTime: _Optional[int] = ..., endTime: _Optional[int] = ..., extraGuestsAllowed: bool = ..., isScheduleCall: bool = ...) -> None: ...

class CommentMessage(_message.Message):
    __slots__ = ("message", "targetMessageKey")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TARGETMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    message: Message
    targetMessageKey: _WACommon_pb2.MessageKey
    def __init__(self, message: _Optional[_Union[Message, _Mapping]] = ..., targetMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...

class EncCommentMessage(_message.Message):
    __slots__ = ("targetMessageKey", "encPayload", "encIV")
    TARGETMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    targetMessageKey: _WACommon_pb2.MessageKey
    encPayload: bytes
    encIV: bytes
    def __init__(self, targetMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ...) -> None: ...

class EncReactionMessage(_message.Message):
    __slots__ = ("targetMessageKey", "encPayload", "encIV")
    TARGETMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    targetMessageKey: _WACommon_pb2.MessageKey
    encPayload: bytes
    encIV: bytes
    def __init__(self, targetMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ...) -> None: ...

class KeepInChatMessage(_message.Message):
    __slots__ = ("key", "keepType", "timestampMS")
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEEPTYPE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    keepType: KeepType
    timestampMS: int
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., keepType: _Optional[_Union[KeepType, str]] = ..., timestampMS: _Optional[int] = ...) -> None: ...

class PollResultSnapshotMessage(_message.Message):
    __slots__ = ("name", "pollVotes", "contextInfo")
    class PollVote(_message.Message):
        __slots__ = ("optionName", "optionVoteCount")
        OPTIONNAME_FIELD_NUMBER: _ClassVar[int]
        OPTIONVOTECOUNT_FIELD_NUMBER: _ClassVar[int]
        optionName: str
        optionVoteCount: int
        def __init__(self, optionName: _Optional[str] = ..., optionVoteCount: _Optional[int] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    POLLVOTES_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    name: str
    pollVotes: _containers.RepeatedCompositeFieldContainer[PollResultSnapshotMessage.PollVote]
    contextInfo: ContextInfo
    def __init__(self, name: _Optional[str] = ..., pollVotes: _Optional[_Iterable[_Union[PollResultSnapshotMessage.PollVote, _Mapping]]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class PollVoteMessage(_message.Message):
    __slots__ = ("selectedOptions",)
    SELECTEDOPTIONS_FIELD_NUMBER: _ClassVar[int]
    selectedOptions: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, selectedOptions: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PollEncValue(_message.Message):
    __slots__ = ("encPayload", "encIV")
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    encPayload: bytes
    encIV: bytes
    def __init__(self, encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ...) -> None: ...

class PollUpdateMessageMetadata(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PollUpdateMessage(_message.Message):
    __slots__ = ("pollCreationMessageKey", "vote", "metadata", "senderTimestampMS")
    POLLCREATIONMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    VOTE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SENDERTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    pollCreationMessageKey: _WACommon_pb2.MessageKey
    vote: PollEncValue
    metadata: PollUpdateMessageMetadata
    senderTimestampMS: int
    def __init__(self, pollCreationMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., vote: _Optional[_Union[PollEncValue, _Mapping]] = ..., metadata: _Optional[_Union[PollUpdateMessageMetadata, _Mapping]] = ..., senderTimestampMS: _Optional[int] = ...) -> None: ...

class StickerSyncRMRMessage(_message.Message):
    __slots__ = ("filehash", "rmrSource", "requestTimestamp")
    FILEHASH_FIELD_NUMBER: _ClassVar[int]
    RMRSOURCE_FIELD_NUMBER: _ClassVar[int]
    REQUESTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    filehash: _containers.RepeatedScalarFieldContainer[str]
    rmrSource: str
    requestTimestamp: int
    def __init__(self, filehash: _Optional[_Iterable[str]] = ..., rmrSource: _Optional[str] = ..., requestTimestamp: _Optional[int] = ...) -> None: ...

class ReactionMessage(_message.Message):
    __slots__ = ("key", "text", "groupingKey", "senderTimestampMS")
    KEY_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    GROUPINGKEY_FIELD_NUMBER: _ClassVar[int]
    SENDERTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    text: str
    groupingKey: str
    senderTimestampMS: int
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., text: _Optional[str] = ..., groupingKey: _Optional[str] = ..., senderTimestampMS: _Optional[int] = ...) -> None: ...

class FutureProofMessage(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: Message
    def __init__(self, message: _Optional[_Union[Message, _Mapping]] = ...) -> None: ...

class DeviceSentMessage(_message.Message):
    __slots__ = ("destinationJID", "message", "phash")
    DESTINATIONJID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    PHASH_FIELD_NUMBER: _ClassVar[int]
    destinationJID: str
    message: Message
    phash: str
    def __init__(self, destinationJID: _Optional[str] = ..., message: _Optional[_Union[Message, _Mapping]] = ..., phash: _Optional[str] = ...) -> None: ...

class RequestPhoneNumberMessage(_message.Message):
    __slots__ = ("contextInfo",)
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    contextInfo: ContextInfo
    def __init__(self, contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class NewsletterAdminInviteMessage(_message.Message):
    __slots__ = ("newsletterJID", "newsletterName", "JPEGThumbnail", "caption", "inviteExpiration", "contextInfo")
    NEWSLETTERJID_FIELD_NUMBER: _ClassVar[int]
    NEWSLETTERNAME_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    INVITEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    newsletterJID: str
    newsletterName: str
    JPEGThumbnail: bytes
    caption: str
    inviteExpiration: int
    contextInfo: ContextInfo
    def __init__(self, newsletterJID: _Optional[str] = ..., newsletterName: _Optional[str] = ..., JPEGThumbnail: _Optional[bytes] = ..., caption: _Optional[str] = ..., inviteExpiration: _Optional[int] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class ProductMessage(_message.Message):
    __slots__ = ("product", "businessOwnerJID", "catalog", "body", "footer", "contextInfo")
    class ProductSnapshot(_message.Message):
        __slots__ = ("productImage", "productID", "title", "description", "currencyCode", "priceAmount1000", "retailerID", "URL", "productImageCount", "firstImageID", "salePriceAmount1000", "signedURL")
        PRODUCTIMAGE_FIELD_NUMBER: _ClassVar[int]
        PRODUCTID_FIELD_NUMBER: _ClassVar[int]
        TITLE_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        CURRENCYCODE_FIELD_NUMBER: _ClassVar[int]
        PRICEAMOUNT1000_FIELD_NUMBER: _ClassVar[int]
        RETAILERID_FIELD_NUMBER: _ClassVar[int]
        URL_FIELD_NUMBER: _ClassVar[int]
        PRODUCTIMAGECOUNT_FIELD_NUMBER: _ClassVar[int]
        FIRSTIMAGEID_FIELD_NUMBER: _ClassVar[int]
        SALEPRICEAMOUNT1000_FIELD_NUMBER: _ClassVar[int]
        SIGNEDURL_FIELD_NUMBER: _ClassVar[int]
        productImage: ImageMessage
        productID: str
        title: str
        description: str
        currencyCode: str
        priceAmount1000: int
        retailerID: str
        URL: str
        productImageCount: int
        firstImageID: str
        salePriceAmount1000: int
        signedURL: str
        def __init__(self, productImage: _Optional[_Union[ImageMessage, _Mapping]] = ..., productID: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., currencyCode: _Optional[str] = ..., priceAmount1000: _Optional[int] = ..., retailerID: _Optional[str] = ..., URL: _Optional[str] = ..., productImageCount: _Optional[int] = ..., firstImageID: _Optional[str] = ..., salePriceAmount1000: _Optional[int] = ..., signedURL: _Optional[str] = ...) -> None: ...
    class CatalogSnapshot(_message.Message):
        __slots__ = ("catalogImage", "title", "description")
        CATALOGIMAGE_FIELD_NUMBER: _ClassVar[int]
        TITLE_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        catalogImage: ImageMessage
        title: str
        description: str
        def __init__(self, catalogImage: _Optional[_Union[ImageMessage, _Mapping]] = ..., title: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...
    PRODUCT_FIELD_NUMBER: _ClassVar[int]
    BUSINESSOWNERJID_FIELD_NUMBER: _ClassVar[int]
    CATALOG_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    FOOTER_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    product: ProductMessage.ProductSnapshot
    businessOwnerJID: str
    catalog: ProductMessage.CatalogSnapshot
    body: str
    footer: str
    contextInfo: ContextInfo
    def __init__(self, product: _Optional[_Union[ProductMessage.ProductSnapshot, _Mapping]] = ..., businessOwnerJID: _Optional[str] = ..., catalog: _Optional[_Union[ProductMessage.CatalogSnapshot, _Mapping]] = ..., body: _Optional[str] = ..., footer: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class TemplateButtonReplyMessage(_message.Message):
    __slots__ = ("selectedID", "selectedDisplayText", "contextInfo", "selectedIndex", "selectedCarouselCardIndex")
    SELECTEDID_FIELD_NUMBER: _ClassVar[int]
    SELECTEDDISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    SELECTEDINDEX_FIELD_NUMBER: _ClassVar[int]
    SELECTEDCAROUSELCARDINDEX_FIELD_NUMBER: _ClassVar[int]
    selectedID: str
    selectedDisplayText: str
    contextInfo: ContextInfo
    selectedIndex: int
    selectedCarouselCardIndex: int
    def __init__(self, selectedID: _Optional[str] = ..., selectedDisplayText: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., selectedIndex: _Optional[int] = ..., selectedCarouselCardIndex: _Optional[int] = ...) -> None: ...

class TemplateMessage(_message.Message):
    __slots__ = ("fourRowTemplate", "hydratedFourRowTemplate", "interactiveMessageTemplate", "contextInfo", "hydratedTemplate", "templateID")
    class HydratedFourRowTemplate(_message.Message):
        __slots__ = ("documentMessage", "hydratedTitleText", "imageMessage", "videoMessage", "locationMessage", "hydratedContentText", "hydratedFooterText", "hydratedButtons", "templateID", "maskLinkedDevices")
        DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        HYDRATEDTITLETEXT_FIELD_NUMBER: _ClassVar[int]
        IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        HYDRATEDCONTENTTEXT_FIELD_NUMBER: _ClassVar[int]
        HYDRATEDFOOTERTEXT_FIELD_NUMBER: _ClassVar[int]
        HYDRATEDBUTTONS_FIELD_NUMBER: _ClassVar[int]
        TEMPLATEID_FIELD_NUMBER: _ClassVar[int]
        MASKLINKEDDEVICES_FIELD_NUMBER: _ClassVar[int]
        documentMessage: DocumentMessage
        hydratedTitleText: str
        imageMessage: ImageMessage
        videoMessage: VideoMessage
        locationMessage: LocationMessage
        hydratedContentText: str
        hydratedFooterText: str
        hydratedButtons: _containers.RepeatedCompositeFieldContainer[HydratedTemplateButton]
        templateID: str
        maskLinkedDevices: bool
        def __init__(self, documentMessage: _Optional[_Union[DocumentMessage, _Mapping]] = ..., hydratedTitleText: _Optional[str] = ..., imageMessage: _Optional[_Union[ImageMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[LocationMessage, _Mapping]] = ..., hydratedContentText: _Optional[str] = ..., hydratedFooterText: _Optional[str] = ..., hydratedButtons: _Optional[_Iterable[_Union[HydratedTemplateButton, _Mapping]]] = ..., templateID: _Optional[str] = ..., maskLinkedDevices: bool = ...) -> None: ...
    class FourRowTemplate(_message.Message):
        __slots__ = ("documentMessage", "highlyStructuredMessage", "imageMessage", "videoMessage", "locationMessage", "content", "footer", "buttons")
        DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        HIGHLYSTRUCTUREDMESSAGE_FIELD_NUMBER: _ClassVar[int]
        IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        CONTENT_FIELD_NUMBER: _ClassVar[int]
        FOOTER_FIELD_NUMBER: _ClassVar[int]
        BUTTONS_FIELD_NUMBER: _ClassVar[int]
        documentMessage: DocumentMessage
        highlyStructuredMessage: HighlyStructuredMessage
        imageMessage: ImageMessage
        videoMessage: VideoMessage
        locationMessage: LocationMessage
        content: HighlyStructuredMessage
        footer: HighlyStructuredMessage
        buttons: _containers.RepeatedCompositeFieldContainer[TemplateButton]
        def __init__(self, documentMessage: _Optional[_Union[DocumentMessage, _Mapping]] = ..., highlyStructuredMessage: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., imageMessage: _Optional[_Union[ImageMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[VideoMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[LocationMessage, _Mapping]] = ..., content: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., footer: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., buttons: _Optional[_Iterable[_Union[TemplateButton, _Mapping]]] = ...) -> None: ...
    FOURROWTEMPLATE_FIELD_NUMBER: _ClassVar[int]
    HYDRATEDFOURROWTEMPLATE_FIELD_NUMBER: _ClassVar[int]
    INTERACTIVEMESSAGETEMPLATE_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    HYDRATEDTEMPLATE_FIELD_NUMBER: _ClassVar[int]
    TEMPLATEID_FIELD_NUMBER: _ClassVar[int]
    fourRowTemplate: TemplateMessage.FourRowTemplate
    hydratedFourRowTemplate: TemplateMessage.HydratedFourRowTemplate
    interactiveMessageTemplate: InteractiveMessage
    contextInfo: ContextInfo
    hydratedTemplate: TemplateMessage.HydratedFourRowTemplate
    templateID: str
    def __init__(self, fourRowTemplate: _Optional[_Union[TemplateMessage.FourRowTemplate, _Mapping]] = ..., hydratedFourRowTemplate: _Optional[_Union[TemplateMessage.HydratedFourRowTemplate, _Mapping]] = ..., interactiveMessageTemplate: _Optional[_Union[InteractiveMessage, _Mapping]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., hydratedTemplate: _Optional[_Union[TemplateMessage.HydratedFourRowTemplate, _Mapping]] = ..., templateID: _Optional[str] = ...) -> None: ...

class StickerMessage(_message.Message):
    __slots__ = ("URL", "fileSHA256", "fileEncSHA256", "mediaKey", "mimetype", "height", "width", "directPath", "fileLength", "mediaKeyTimestamp", "firstFrameLength", "firstFrameSidecar", "isAnimated", "pngThumbnail", "contextInfo", "stickerSentTS", "isAvatar", "isAiSticker", "isLottie", "accessibilityLabel")
    URL_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    FIRSTFRAMELENGTH_FIELD_NUMBER: _ClassVar[int]
    FIRSTFRAMESIDECAR_FIELD_NUMBER: _ClassVar[int]
    ISANIMATED_FIELD_NUMBER: _ClassVar[int]
    PNGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    STICKERSENTTS_FIELD_NUMBER: _ClassVar[int]
    ISAVATAR_FIELD_NUMBER: _ClassVar[int]
    ISAISTICKER_FIELD_NUMBER: _ClassVar[int]
    ISLOTTIE_FIELD_NUMBER: _ClassVar[int]
    ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
    URL: str
    fileSHA256: bytes
    fileEncSHA256: bytes
    mediaKey: bytes
    mimetype: str
    height: int
    width: int
    directPath: str
    fileLength: int
    mediaKeyTimestamp: int
    firstFrameLength: int
    firstFrameSidecar: bytes
    isAnimated: bool
    pngThumbnail: bytes
    contextInfo: ContextInfo
    stickerSentTS: int
    isAvatar: bool
    isAiSticker: bool
    isLottie: bool
    accessibilityLabel: str
    def __init__(self, URL: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., mimetype: _Optional[str] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., directPath: _Optional[str] = ..., fileLength: _Optional[int] = ..., mediaKeyTimestamp: _Optional[int] = ..., firstFrameLength: _Optional[int] = ..., firstFrameSidecar: _Optional[bytes] = ..., isAnimated: bool = ..., pngThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., stickerSentTS: _Optional[int] = ..., isAvatar: bool = ..., isAiSticker: bool = ..., isLottie: bool = ..., accessibilityLabel: _Optional[str] = ...) -> None: ...

class LiveLocationMessage(_message.Message):
    __slots__ = ("degreesLatitude", "degreesLongitude", "accuracyInMeters", "speedInMps", "degreesClockwiseFromMagneticNorth", "caption", "sequenceNumber", "timeOffset", "JPEGThumbnail", "contextInfo")
    DEGREESLATITUDE_FIELD_NUMBER: _ClassVar[int]
    DEGREESLONGITUDE_FIELD_NUMBER: _ClassVar[int]
    ACCURACYINMETERS_FIELD_NUMBER: _ClassVar[int]
    SPEEDINMPS_FIELD_NUMBER: _ClassVar[int]
    DEGREESCLOCKWISEFROMMAGNETICNORTH_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    SEQUENCENUMBER_FIELD_NUMBER: _ClassVar[int]
    TIMEOFFSET_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    degreesLatitude: float
    degreesLongitude: float
    accuracyInMeters: int
    speedInMps: float
    degreesClockwiseFromMagneticNorth: int
    caption: str
    sequenceNumber: int
    timeOffset: int
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    def __init__(self, degreesLatitude: _Optional[float] = ..., degreesLongitude: _Optional[float] = ..., accuracyInMeters: _Optional[int] = ..., speedInMps: _Optional[float] = ..., degreesClockwiseFromMagneticNorth: _Optional[int] = ..., caption: _Optional[str] = ..., sequenceNumber: _Optional[int] = ..., timeOffset: _Optional[int] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class CancelPaymentRequestMessage(_message.Message):
    __slots__ = ("key",)
    KEY_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...

class DeclinePaymentRequestMessage(_message.Message):
    __slots__ = ("key",)
    KEY_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...

class RequestPaymentMessage(_message.Message):
    __slots__ = ("noteMessage", "currencyCodeIso4217", "amount1000", "requestFrom", "expiryTimestamp", "amount", "background")
    NOTEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CURRENCYCODEISO4217_FIELD_NUMBER: _ClassVar[int]
    AMOUNT1000_FIELD_NUMBER: _ClassVar[int]
    REQUESTFROM_FIELD_NUMBER: _ClassVar[int]
    EXPIRYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_FIELD_NUMBER: _ClassVar[int]
    BACKGROUND_FIELD_NUMBER: _ClassVar[int]
    noteMessage: Message
    currencyCodeIso4217: str
    amount1000: int
    requestFrom: str
    expiryTimestamp: int
    amount: Money
    background: PaymentBackground
    def __init__(self, noteMessage: _Optional[_Union[Message, _Mapping]] = ..., currencyCodeIso4217: _Optional[str] = ..., amount1000: _Optional[int] = ..., requestFrom: _Optional[str] = ..., expiryTimestamp: _Optional[int] = ..., amount: _Optional[_Union[Money, _Mapping]] = ..., background: _Optional[_Union[PaymentBackground, _Mapping]] = ...) -> None: ...

class SendPaymentMessage(_message.Message):
    __slots__ = ("noteMessage", "requestMessageKey", "background")
    NOTEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REQUESTMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    BACKGROUND_FIELD_NUMBER: _ClassVar[int]
    noteMessage: Message
    requestMessageKey: _WACommon_pb2.MessageKey
    background: PaymentBackground
    def __init__(self, noteMessage: _Optional[_Union[Message, _Mapping]] = ..., requestMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., background: _Optional[_Union[PaymentBackground, _Mapping]] = ...) -> None: ...

class ContactsArrayMessage(_message.Message):
    __slots__ = ("displayName", "contacts", "contextInfo")
    DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
    CONTACTS_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    displayName: str
    contacts: _containers.RepeatedCompositeFieldContainer[ContactMessage]
    contextInfo: ContextInfo
    def __init__(self, displayName: _Optional[str] = ..., contacts: _Optional[_Iterable[_Union[ContactMessage, _Mapping]]] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class InitialSecurityNotificationSettingSync(_message.Message):
    __slots__ = ("securityNotificationEnabled",)
    SECURITYNOTIFICATIONENABLED_FIELD_NUMBER: _ClassVar[int]
    securityNotificationEnabled: bool
    def __init__(self, securityNotificationEnabled: bool = ...) -> None: ...

class PeerDataOperationRequestMessage(_message.Message):
    __slots__ = ("peerDataOperationRequestType", "requestStickerReupload", "requestURLPreview", "historySyncOnDemandRequest", "placeholderMessageResendRequest", "fullHistorySyncOnDemandRequest", "syncdCollectionFatalRecoveryRequest")
    class SyncDCollectionFatalRecoveryRequest(_message.Message):
        __slots__ = ("collectionName", "timestamp")
        COLLECTIONNAME_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        collectionName: str
        timestamp: int
        def __init__(self, collectionName: _Optional[str] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class PlaceholderMessageResendRequest(_message.Message):
        __slots__ = ("messageKey",)
        MESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
        messageKey: _WACommon_pb2.MessageKey
        def __init__(self, messageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...
    class FullHistorySyncOnDemandRequest(_message.Message):
        __slots__ = ("requestMetadata", "historySyncConfig")
        REQUESTMETADATA_FIELD_NUMBER: _ClassVar[int]
        HISTORYSYNCCONFIG_FIELD_NUMBER: _ClassVar[int]
        requestMetadata: FullHistorySyncOnDemandRequestMetadata
        historySyncConfig: _WACompanionReg_pb2.DeviceProps.HistorySyncConfig
        def __init__(self, requestMetadata: _Optional[_Union[FullHistorySyncOnDemandRequestMetadata, _Mapping]] = ..., historySyncConfig: _Optional[_Union[_WACompanionReg_pb2.DeviceProps.HistorySyncConfig, _Mapping]] = ...) -> None: ...
    class HistorySyncOnDemandRequest(_message.Message):
        __slots__ = ("chatJID", "oldestMsgID", "oldestMsgFromMe", "onDemandMsgCount", "oldestMsgTimestampMS", "accountLid")
        CHATJID_FIELD_NUMBER: _ClassVar[int]
        OLDESTMSGID_FIELD_NUMBER: _ClassVar[int]
        OLDESTMSGFROMME_FIELD_NUMBER: _ClassVar[int]
        ONDEMANDMSGCOUNT_FIELD_NUMBER: _ClassVar[int]
        OLDESTMSGTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
        ACCOUNTLID_FIELD_NUMBER: _ClassVar[int]
        chatJID: str
        oldestMsgID: str
        oldestMsgFromMe: bool
        onDemandMsgCount: int
        oldestMsgTimestampMS: int
        accountLid: str
        def __init__(self, chatJID: _Optional[str] = ..., oldestMsgID: _Optional[str] = ..., oldestMsgFromMe: bool = ..., onDemandMsgCount: _Optional[int] = ..., oldestMsgTimestampMS: _Optional[int] = ..., accountLid: _Optional[str] = ...) -> None: ...
    class RequestUrlPreview(_message.Message):
        __slots__ = ("URL", "includeHqThumbnail")
        URL_FIELD_NUMBER: _ClassVar[int]
        INCLUDEHQTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        URL: str
        includeHqThumbnail: bool
        def __init__(self, URL: _Optional[str] = ..., includeHqThumbnail: bool = ...) -> None: ...
    class RequestStickerReupload(_message.Message):
        __slots__ = ("fileSHA256",)
        FILESHA256_FIELD_NUMBER: _ClassVar[int]
        fileSHA256: str
        def __init__(self, fileSHA256: _Optional[str] = ...) -> None: ...
    PEERDATAOPERATIONREQUESTTYPE_FIELD_NUMBER: _ClassVar[int]
    REQUESTSTICKERREUPLOAD_FIELD_NUMBER: _ClassVar[int]
    REQUESTURLPREVIEW_FIELD_NUMBER: _ClassVar[int]
    HISTORYSYNCONDEMANDREQUEST_FIELD_NUMBER: _ClassVar[int]
    PLACEHOLDERMESSAGERESENDREQUEST_FIELD_NUMBER: _ClassVar[int]
    FULLHISTORYSYNCONDEMANDREQUEST_FIELD_NUMBER: _ClassVar[int]
    SYNCDCOLLECTIONFATALRECOVERYREQUEST_FIELD_NUMBER: _ClassVar[int]
    peerDataOperationRequestType: PeerDataOperationRequestType
    requestStickerReupload: _containers.RepeatedCompositeFieldContainer[PeerDataOperationRequestMessage.RequestStickerReupload]
    requestURLPreview: _containers.RepeatedCompositeFieldContainer[PeerDataOperationRequestMessage.RequestUrlPreview]
    historySyncOnDemandRequest: PeerDataOperationRequestMessage.HistorySyncOnDemandRequest
    placeholderMessageResendRequest: _containers.RepeatedCompositeFieldContainer[PeerDataOperationRequestMessage.PlaceholderMessageResendRequest]
    fullHistorySyncOnDemandRequest: PeerDataOperationRequestMessage.FullHistorySyncOnDemandRequest
    syncdCollectionFatalRecoveryRequest: PeerDataOperationRequestMessage.SyncDCollectionFatalRecoveryRequest
    def __init__(self, peerDataOperationRequestType: _Optional[_Union[PeerDataOperationRequestType, str]] = ..., requestStickerReupload: _Optional[_Iterable[_Union[PeerDataOperationRequestMessage.RequestStickerReupload, _Mapping]]] = ..., requestURLPreview: _Optional[_Iterable[_Union[PeerDataOperationRequestMessage.RequestUrlPreview, _Mapping]]] = ..., historySyncOnDemandRequest: _Optional[_Union[PeerDataOperationRequestMessage.HistorySyncOnDemandRequest, _Mapping]] = ..., placeholderMessageResendRequest: _Optional[_Iterable[_Union[PeerDataOperationRequestMessage.PlaceholderMessageResendRequest, _Mapping]]] = ..., fullHistorySyncOnDemandRequest: _Optional[_Union[PeerDataOperationRequestMessage.FullHistorySyncOnDemandRequest, _Mapping]] = ..., syncdCollectionFatalRecoveryRequest: _Optional[_Union[PeerDataOperationRequestMessage.SyncDCollectionFatalRecoveryRequest, _Mapping]] = ...) -> None: ...

class FullHistorySyncOnDemandRequestMetadata(_message.Message):
    __slots__ = ("requestID",)
    REQUESTID_FIELD_NUMBER: _ClassVar[int]
    requestID: str
    def __init__(self, requestID: _Optional[str] = ...) -> None: ...

class AppStateFatalExceptionNotification(_message.Message):
    __slots__ = ("collectionNames", "timestamp")
    COLLECTIONNAMES_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    collectionNames: _containers.RepeatedScalarFieldContainer[str]
    timestamp: int
    def __init__(self, collectionNames: _Optional[_Iterable[str]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class AppStateSyncKeyRequest(_message.Message):
    __slots__ = ("keyIDs",)
    KEYIDS_FIELD_NUMBER: _ClassVar[int]
    keyIDs: _containers.RepeatedCompositeFieldContainer[AppStateSyncKeyId]
    def __init__(self, keyIDs: _Optional[_Iterable[_Union[AppStateSyncKeyId, _Mapping]]] = ...) -> None: ...

class AppStateSyncKeyShare(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[AppStateSyncKey]
    def __init__(self, keys: _Optional[_Iterable[_Union[AppStateSyncKey, _Mapping]]] = ...) -> None: ...

class AppStateSyncKeyData(_message.Message):
    __slots__ = ("keyData", "fingerprint", "timestamp")
    KEYDATA_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    keyData: bytes
    fingerprint: AppStateSyncKeyFingerprint
    timestamp: int
    def __init__(self, keyData: _Optional[bytes] = ..., fingerprint: _Optional[_Union[AppStateSyncKeyFingerprint, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class AppStateSyncKeyFingerprint(_message.Message):
    __slots__ = ("rawID", "currentIndex", "deviceIndexes")
    RAWID_FIELD_NUMBER: _ClassVar[int]
    CURRENTINDEX_FIELD_NUMBER: _ClassVar[int]
    DEVICEINDEXES_FIELD_NUMBER: _ClassVar[int]
    rawID: int
    currentIndex: int
    deviceIndexes: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, rawID: _Optional[int] = ..., currentIndex: _Optional[int] = ..., deviceIndexes: _Optional[_Iterable[int]] = ...) -> None: ...

class AppStateSyncKeyId(_message.Message):
    __slots__ = ("keyID",)
    KEYID_FIELD_NUMBER: _ClassVar[int]
    keyID: bytes
    def __init__(self, keyID: _Optional[bytes] = ...) -> None: ...

class AppStateSyncKey(_message.Message):
    __slots__ = ("keyID", "keyData")
    KEYID_FIELD_NUMBER: _ClassVar[int]
    KEYDATA_FIELD_NUMBER: _ClassVar[int]
    keyID: AppStateSyncKeyId
    keyData: AppStateSyncKeyData
    def __init__(self, keyID: _Optional[_Union[AppStateSyncKeyId, _Mapping]] = ..., keyData: _Optional[_Union[AppStateSyncKeyData, _Mapping]] = ...) -> None: ...

class Chat(_message.Message):
    __slots__ = ("displayName", "ID")
    DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    displayName: str
    ID: str
    def __init__(self, displayName: _Optional[str] = ..., ID: _Optional[str] = ...) -> None: ...

class Call(_message.Message):
    __slots__ = ("callKey", "conversionSource", "conversionData", "conversionDelaySeconds", "ctwaSignals", "ctwaPayload", "contextInfo")
    CALLKEY_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONSOURCE_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONDATA_FIELD_NUMBER: _ClassVar[int]
    CONVERSIONDELAYSECONDS_FIELD_NUMBER: _ClassVar[int]
    CTWASIGNALS_FIELD_NUMBER: _ClassVar[int]
    CTWAPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    callKey: bytes
    conversionSource: str
    conversionData: bytes
    conversionDelaySeconds: int
    ctwaSignals: str
    ctwaPayload: bytes
    contextInfo: ContextInfo
    def __init__(self, callKey: _Optional[bytes] = ..., conversionSource: _Optional[str] = ..., conversionData: _Optional[bytes] = ..., conversionDelaySeconds: _Optional[int] = ..., ctwaSignals: _Optional[str] = ..., ctwaPayload: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class AudioMessage(_message.Message):
    __slots__ = ("URL", "mimetype", "fileSHA256", "fileLength", "seconds", "PTT", "mediaKey", "fileEncSHA256", "directPath", "mediaKeyTimestamp", "contextInfo", "streamingSidecar", "waveform", "backgroundArgb", "viewOnce", "accessibilityLabel")
    URL_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    SECONDS_FIELD_NUMBER: _ClassVar[int]
    PTT_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    STREAMINGSIDECAR_FIELD_NUMBER: _ClassVar[int]
    WAVEFORM_FIELD_NUMBER: _ClassVar[int]
    BACKGROUNDARGB_FIELD_NUMBER: _ClassVar[int]
    VIEWONCE_FIELD_NUMBER: _ClassVar[int]
    ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
    URL: str
    mimetype: str
    fileSHA256: bytes
    fileLength: int
    seconds: int
    PTT: bool
    mediaKey: bytes
    fileEncSHA256: bytes
    directPath: str
    mediaKeyTimestamp: int
    contextInfo: ContextInfo
    streamingSidecar: bytes
    waveform: bytes
    backgroundArgb: int
    viewOnce: bool
    accessibilityLabel: str
    def __init__(self, URL: _Optional[str] = ..., mimetype: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ..., seconds: _Optional[int] = ..., PTT: bool = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., streamingSidecar: _Optional[bytes] = ..., waveform: _Optional[bytes] = ..., backgroundArgb: _Optional[int] = ..., viewOnce: bool = ..., accessibilityLabel: _Optional[str] = ...) -> None: ...

class DocumentMessage(_message.Message):
    __slots__ = ("URL", "mimetype", "title", "fileSHA256", "fileLength", "pageCount", "mediaKey", "fileName", "fileEncSHA256", "directPath", "mediaKeyTimestamp", "contactVcard", "thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "JPEGThumbnail", "contextInfo", "thumbnailHeight", "thumbnailWidth", "caption", "accessibilityLabel")
    URL_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    PAGECOUNT_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CONTACTVCARD_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILHEIGHT_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILWIDTH_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
    URL: str
    mimetype: str
    title: str
    fileSHA256: bytes
    fileLength: int
    pageCount: int
    mediaKey: bytes
    fileName: str
    fileEncSHA256: bytes
    directPath: str
    mediaKeyTimestamp: int
    contactVcard: bool
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    thumbnailHeight: int
    thumbnailWidth: int
    caption: str
    accessibilityLabel: str
    def __init__(self, URL: _Optional[str] = ..., mimetype: _Optional[str] = ..., title: _Optional[str] = ..., fileSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ..., pageCount: _Optional[int] = ..., mediaKey: _Optional[bytes] = ..., fileName: _Optional[str] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., contactVcard: bool = ..., thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ..., thumbnailHeight: _Optional[int] = ..., thumbnailWidth: _Optional[int] = ..., caption: _Optional[str] = ..., accessibilityLabel: _Optional[str] = ...) -> None: ...

class LinkPreviewMetadata(_message.Message):
    __slots__ = ("paymentLinkMetadata", "urlMetadata", "fbExperimentID")
    PAYMENTLINKMETADATA_FIELD_NUMBER: _ClassVar[int]
    URLMETADATA_FIELD_NUMBER: _ClassVar[int]
    FBEXPERIMENTID_FIELD_NUMBER: _ClassVar[int]
    paymentLinkMetadata: PaymentLinkMetadata
    urlMetadata: URLMetadata
    fbExperimentID: int
    def __init__(self, paymentLinkMetadata: _Optional[_Union[PaymentLinkMetadata, _Mapping]] = ..., urlMetadata: _Optional[_Union[URLMetadata, _Mapping]] = ..., fbExperimentID: _Optional[int] = ...) -> None: ...

class URLMetadata(_message.Message):
    __slots__ = ("fbExperimentID",)
    FBEXPERIMENTID_FIELD_NUMBER: _ClassVar[int]
    fbExperimentID: int
    def __init__(self, fbExperimentID: _Optional[int] = ...) -> None: ...

class MMSThumbnailMetadata(_message.Message):
    __slots__ = ("thumbnailDirectPath", "thumbnailSHA256", "thumbnailEncSHA256", "mediaKey", "mediaKeyTimestamp", "thumbnailHeight", "thumbnailWidth")
    THUMBNAILDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILSHA256_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILHEIGHT_FIELD_NUMBER: _ClassVar[int]
    THUMBNAILWIDTH_FIELD_NUMBER: _ClassVar[int]
    thumbnailDirectPath: str
    thumbnailSHA256: bytes
    thumbnailEncSHA256: bytes
    mediaKey: bytes
    mediaKeyTimestamp: int
    thumbnailHeight: int
    thumbnailWidth: int
    def __init__(self, thumbnailDirectPath: _Optional[str] = ..., thumbnailSHA256: _Optional[bytes] = ..., thumbnailEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., thumbnailHeight: _Optional[int] = ..., thumbnailWidth: _Optional[int] = ...) -> None: ...

class LocationMessage(_message.Message):
    __slots__ = ("degreesLatitude", "degreesLongitude", "name", "address", "URL", "isLive", "accuracyInMeters", "speedInMps", "degreesClockwiseFromMagneticNorth", "comment", "JPEGThumbnail", "contextInfo")
    DEGREESLATITUDE_FIELD_NUMBER: _ClassVar[int]
    DEGREESLONGITUDE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    ISLIVE_FIELD_NUMBER: _ClassVar[int]
    ACCURACYINMETERS_FIELD_NUMBER: _ClassVar[int]
    SPEEDINMPS_FIELD_NUMBER: _ClassVar[int]
    DEGREESCLOCKWISEFROMMAGNETICNORTH_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    degreesLatitude: float
    degreesLongitude: float
    name: str
    address: str
    URL: str
    isLive: bool
    accuracyInMeters: int
    speedInMps: float
    degreesClockwiseFromMagneticNorth: int
    comment: str
    JPEGThumbnail: bytes
    contextInfo: ContextInfo
    def __init__(self, degreesLatitude: _Optional[float] = ..., degreesLongitude: _Optional[float] = ..., name: _Optional[str] = ..., address: _Optional[str] = ..., URL: _Optional[str] = ..., isLive: bool = ..., accuracyInMeters: _Optional[int] = ..., speedInMps: _Optional[float] = ..., degreesClockwiseFromMagneticNorth: _Optional[int] = ..., comment: _Optional[str] = ..., JPEGThumbnail: _Optional[bytes] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class ContactMessage(_message.Message):
    __slots__ = ("displayName", "vcard", "contextInfo")
    DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
    VCARD_FIELD_NUMBER: _ClassVar[int]
    CONTEXTINFO_FIELD_NUMBER: _ClassVar[int]
    displayName: str
    vcard: str
    contextInfo: ContextInfo
    def __init__(self, displayName: _Optional[str] = ..., vcard: _Optional[str] = ..., contextInfo: _Optional[_Union[ContextInfo, _Mapping]] = ...) -> None: ...

class SenderKeyDistributionMessage(_message.Message):
    __slots__ = ("groupID", "axolotlSenderKeyDistributionMessage")
    GROUPID_FIELD_NUMBER: _ClassVar[int]
    AXOLOTLSENDERKEYDISTRIBUTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    groupID: str
    axolotlSenderKeyDistributionMessage: bytes
    def __init__(self, groupID: _Optional[str] = ..., axolotlSenderKeyDistributionMessage: _Optional[bytes] = ...) -> None: ...

class BotAvatarMetadata(_message.Message):
    __slots__ = ("sentiment", "behaviorGraph", "action", "intensity", "wordCount")
    SENTIMENT_FIELD_NUMBER: _ClassVar[int]
    BEHAVIORGRAPH_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    INTENSITY_FIELD_NUMBER: _ClassVar[int]
    WORDCOUNT_FIELD_NUMBER: _ClassVar[int]
    sentiment: int
    behaviorGraph: str
    action: int
    intensity: int
    wordCount: int
    def __init__(self, sentiment: _Optional[int] = ..., behaviorGraph: _Optional[str] = ..., action: _Optional[int] = ..., intensity: _Optional[int] = ..., wordCount: _Optional[int] = ...) -> None: ...

class BotSuggestedPromptMetadata(_message.Message):
    __slots__ = ("suggestedPrompts", "selectedPromptIndex", "promptSuggestions", "selectedPromptID")
    SUGGESTEDPROMPTS_FIELD_NUMBER: _ClassVar[int]
    SELECTEDPROMPTINDEX_FIELD_NUMBER: _ClassVar[int]
    PROMPTSUGGESTIONS_FIELD_NUMBER: _ClassVar[int]
    SELECTEDPROMPTID_FIELD_NUMBER: _ClassVar[int]
    suggestedPrompts: _containers.RepeatedScalarFieldContainer[str]
    selectedPromptIndex: int
    promptSuggestions: BotPromptSuggestions
    selectedPromptID: str
    def __init__(self, suggestedPrompts: _Optional[_Iterable[str]] = ..., selectedPromptIndex: _Optional[int] = ..., promptSuggestions: _Optional[_Union[BotPromptSuggestions, _Mapping]] = ..., selectedPromptID: _Optional[str] = ...) -> None: ...

class BotPromptSuggestions(_message.Message):
    __slots__ = ("suggestions",)
    SUGGESTIONS_FIELD_NUMBER: _ClassVar[int]
    suggestions: _containers.RepeatedCompositeFieldContainer[BotPromptSuggestion]
    def __init__(self, suggestions: _Optional[_Iterable[_Union[BotPromptSuggestion, _Mapping]]] = ...) -> None: ...

class BotPromptSuggestion(_message.Message):
    __slots__ = ("prompt", "promptID")
    PROMPT_FIELD_NUMBER: _ClassVar[int]
    PROMPTID_FIELD_NUMBER: _ClassVar[int]
    prompt: str
    promptID: str
    def __init__(self, prompt: _Optional[str] = ..., promptID: _Optional[str] = ...) -> None: ...

class BotLinkedAccountsMetadata(_message.Message):
    __slots__ = ("accounts", "acAuthTokens", "acErrorCode")
    ACCOUNTS_FIELD_NUMBER: _ClassVar[int]
    ACAUTHTOKENS_FIELD_NUMBER: _ClassVar[int]
    ACERRORCODE_FIELD_NUMBER: _ClassVar[int]
    accounts: _containers.RepeatedCompositeFieldContainer[BotLinkedAccount]
    acAuthTokens: bytes
    acErrorCode: int
    def __init__(self, accounts: _Optional[_Iterable[_Union[BotLinkedAccount, _Mapping]]] = ..., acAuthTokens: _Optional[bytes] = ..., acErrorCode: _Optional[int] = ...) -> None: ...

class BotMemoryMetadata(_message.Message):
    __slots__ = ("addedFacts", "removedFacts", "disclaimer")
    ADDEDFACTS_FIELD_NUMBER: _ClassVar[int]
    REMOVEDFACTS_FIELD_NUMBER: _ClassVar[int]
    DISCLAIMER_FIELD_NUMBER: _ClassVar[int]
    addedFacts: _containers.RepeatedCompositeFieldContainer[BotMemoryFact]
    removedFacts: _containers.RepeatedCompositeFieldContainer[BotMemoryFact]
    disclaimer: str
    def __init__(self, addedFacts: _Optional[_Iterable[_Union[BotMemoryFact, _Mapping]]] = ..., removedFacts: _Optional[_Iterable[_Union[BotMemoryFact, _Mapping]]] = ..., disclaimer: _Optional[str] = ...) -> None: ...

class BotMemoryFact(_message.Message):
    __slots__ = ("fact", "factID")
    FACT_FIELD_NUMBER: _ClassVar[int]
    FACTID_FIELD_NUMBER: _ClassVar[int]
    fact: str
    factID: str
    def __init__(self, fact: _Optional[str] = ..., factID: _Optional[str] = ...) -> None: ...

class BotRenderingMetadata(_message.Message):
    __slots__ = ("keywords",)
    class Keyword(_message.Message):
        __slots__ = ("value", "associatedPrompts")
        VALUE_FIELD_NUMBER: _ClassVar[int]
        ASSOCIATEDPROMPTS_FIELD_NUMBER: _ClassVar[int]
        value: str
        associatedPrompts: _containers.RepeatedScalarFieldContainer[str]
        def __init__(self, value: _Optional[str] = ..., associatedPrompts: _Optional[_Iterable[str]] = ...) -> None: ...
    KEYWORDS_FIELD_NUMBER: _ClassVar[int]
    keywords: _containers.RepeatedCompositeFieldContainer[BotRenderingMetadata.Keyword]
    def __init__(self, keywords: _Optional[_Iterable[_Union[BotRenderingMetadata.Keyword, _Mapping]]] = ...) -> None: ...

class BotMetricsMetadata(_message.Message):
    __slots__ = ("destinationID", "destinationEntryPoint", "threadOrigin")
    DESTINATIONID_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONENTRYPOINT_FIELD_NUMBER: _ClassVar[int]
    THREADORIGIN_FIELD_NUMBER: _ClassVar[int]
    destinationID: str
    destinationEntryPoint: BotMetricsEntryPoint
    threadOrigin: BotMetricsThreadEntryPoint
    def __init__(self, destinationID: _Optional[str] = ..., destinationEntryPoint: _Optional[_Union[BotMetricsEntryPoint, str]] = ..., threadOrigin: _Optional[_Union[BotMetricsThreadEntryPoint, str]] = ...) -> None: ...

class BotSessionMetadata(_message.Message):
    __slots__ = ("sessionID", "sessionSource")
    SESSIONID_FIELD_NUMBER: _ClassVar[int]
    SESSIONSOURCE_FIELD_NUMBER: _ClassVar[int]
    sessionID: str
    sessionSource: BotSessionSource
    def __init__(self, sessionID: _Optional[str] = ..., sessionSource: _Optional[_Union[BotSessionSource, str]] = ...) -> None: ...

class BotMemuMetadata(_message.Message):
    __slots__ = ("faceImages",)
    FACEIMAGES_FIELD_NUMBER: _ClassVar[int]
    faceImages: _containers.RepeatedCompositeFieldContainer[BotMediaMetadata]
    def __init__(self, faceImages: _Optional[_Iterable[_Union[BotMediaMetadata, _Mapping]]] = ...) -> None: ...

class BotAgeCollectionMetadata(_message.Message):
    __slots__ = ("ageCollectionEligible", "shouldTriggerAgeCollectionOnClient")
    AGECOLLECTIONELIGIBLE_FIELD_NUMBER: _ClassVar[int]
    SHOULDTRIGGERAGECOLLECTIONONCLIENT_FIELD_NUMBER: _ClassVar[int]
    ageCollectionEligible: bool
    shouldTriggerAgeCollectionOnClient: bool
    def __init__(self, ageCollectionEligible: bool = ..., shouldTriggerAgeCollectionOnClient: bool = ...) -> None: ...

class BotMetadata(_message.Message):
    __slots__ = ("avatarMetadata", "personaID", "pluginMetadata", "suggestedPromptMetadata", "invokerJID", "sessionMetadata", "memuMetadata", "timezone", "reminderMetadata", "modelMetadata", "messageDisclaimerText", "progressIndicatorMetadata", "capabilityMetadata", "imagineMetadata", "memoryMetadata", "renderingMetadata", "botMetricsMetadata", "botLinkedAccountsMetadata", "richResponseSourcesMetadata", "aiConversationContext", "botPromotionMessageMetadata", "botModeSelectionMetadata", "botQuotaMetadata", "botAgeCollectionMetadata")
    AVATARMETADATA_FIELD_NUMBER: _ClassVar[int]
    PERSONAID_FIELD_NUMBER: _ClassVar[int]
    PLUGINMETADATA_FIELD_NUMBER: _ClassVar[int]
    SUGGESTEDPROMPTMETADATA_FIELD_NUMBER: _ClassVar[int]
    INVOKERJID_FIELD_NUMBER: _ClassVar[int]
    SESSIONMETADATA_FIELD_NUMBER: _ClassVar[int]
    MEMUMETADATA_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    REMINDERMETADATA_FIELD_NUMBER: _ClassVar[int]
    MODELMETADATA_FIELD_NUMBER: _ClassVar[int]
    MESSAGEDISCLAIMERTEXT_FIELD_NUMBER: _ClassVar[int]
    PROGRESSINDICATORMETADATA_FIELD_NUMBER: _ClassVar[int]
    CAPABILITYMETADATA_FIELD_NUMBER: _ClassVar[int]
    IMAGINEMETADATA_FIELD_NUMBER: _ClassVar[int]
    MEMORYMETADATA_FIELD_NUMBER: _ClassVar[int]
    RENDERINGMETADATA_FIELD_NUMBER: _ClassVar[int]
    BOTMETRICSMETADATA_FIELD_NUMBER: _ClassVar[int]
    BOTLINKEDACCOUNTSMETADATA_FIELD_NUMBER: _ClassVar[int]
    RICHRESPONSESOURCESMETADATA_FIELD_NUMBER: _ClassVar[int]
    AICONVERSATIONCONTEXT_FIELD_NUMBER: _ClassVar[int]
    BOTPROMOTIONMESSAGEMETADATA_FIELD_NUMBER: _ClassVar[int]
    BOTMODESELECTIONMETADATA_FIELD_NUMBER: _ClassVar[int]
    BOTQUOTAMETADATA_FIELD_NUMBER: _ClassVar[int]
    BOTAGECOLLECTIONMETADATA_FIELD_NUMBER: _ClassVar[int]
    avatarMetadata: BotAvatarMetadata
    personaID: str
    pluginMetadata: BotPluginMetadata
    suggestedPromptMetadata: BotSuggestedPromptMetadata
    invokerJID: str
    sessionMetadata: BotSessionMetadata
    memuMetadata: BotMemuMetadata
    timezone: str
    reminderMetadata: BotReminderMetadata
    modelMetadata: BotModelMetadata
    messageDisclaimerText: str
    progressIndicatorMetadata: BotProgressIndicatorMetadata
    capabilityMetadata: BotCapabilityMetadata
    imagineMetadata: BotImagineMetadata
    memoryMetadata: BotMemoryMetadata
    renderingMetadata: BotRenderingMetadata
    botMetricsMetadata: BotMetricsMetadata
    botLinkedAccountsMetadata: BotLinkedAccountsMetadata
    richResponseSourcesMetadata: BotSourcesMetadata
    aiConversationContext: bytes
    botPromotionMessageMetadata: BotPromotionMessageMetadata
    botModeSelectionMetadata: BotModeSelectionMetadata
    botQuotaMetadata: BotQuotaMetadata
    botAgeCollectionMetadata: BotAgeCollectionMetadata
    def __init__(self, avatarMetadata: _Optional[_Union[BotAvatarMetadata, _Mapping]] = ..., personaID: _Optional[str] = ..., pluginMetadata: _Optional[_Union[BotPluginMetadata, _Mapping]] = ..., suggestedPromptMetadata: _Optional[_Union[BotSuggestedPromptMetadata, _Mapping]] = ..., invokerJID: _Optional[str] = ..., sessionMetadata: _Optional[_Union[BotSessionMetadata, _Mapping]] = ..., memuMetadata: _Optional[_Union[BotMemuMetadata, _Mapping]] = ..., timezone: _Optional[str] = ..., reminderMetadata: _Optional[_Union[BotReminderMetadata, _Mapping]] = ..., modelMetadata: _Optional[_Union[BotModelMetadata, _Mapping]] = ..., messageDisclaimerText: _Optional[str] = ..., progressIndicatorMetadata: _Optional[_Union[BotProgressIndicatorMetadata, _Mapping]] = ..., capabilityMetadata: _Optional[_Union[BotCapabilityMetadata, _Mapping]] = ..., imagineMetadata: _Optional[_Union[BotImagineMetadata, _Mapping]] = ..., memoryMetadata: _Optional[_Union[BotMemoryMetadata, _Mapping]] = ..., renderingMetadata: _Optional[_Union[BotRenderingMetadata, _Mapping]] = ..., botMetricsMetadata: _Optional[_Union[BotMetricsMetadata, _Mapping]] = ..., botLinkedAccountsMetadata: _Optional[_Union[BotLinkedAccountsMetadata, _Mapping]] = ..., richResponseSourcesMetadata: _Optional[_Union[BotSourcesMetadata, _Mapping]] = ..., aiConversationContext: _Optional[bytes] = ..., botPromotionMessageMetadata: _Optional[_Union[BotPromotionMessageMetadata, _Mapping]] = ..., botModeSelectionMetadata: _Optional[_Union[BotModeSelectionMetadata, _Mapping]] = ..., botQuotaMetadata: _Optional[_Union[BotQuotaMetadata, _Mapping]] = ..., botAgeCollectionMetadata: _Optional[_Union[BotAgeCollectionMetadata, _Mapping]] = ...) -> None: ...

class DeviceListMetadata(_message.Message):
    __slots__ = ("senderKeyHash", "senderTimestamp", "senderKeyIndexes", "senderAccountType", "receiverAccountType", "recipientKeyHash", "recipientTimestamp", "recipientKeyIndexes")
    SENDERKEYHASH_FIELD_NUMBER: _ClassVar[int]
    SENDERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SENDERKEYINDEXES_FIELD_NUMBER: _ClassVar[int]
    SENDERACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    RECEIVERACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTKEYHASH_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTKEYINDEXES_FIELD_NUMBER: _ClassVar[int]
    senderKeyHash: bytes
    senderTimestamp: int
    senderKeyIndexes: _containers.RepeatedScalarFieldContainer[int]
    senderAccountType: _WAAdv_pb2.ADVEncryptionType
    receiverAccountType: _WAAdv_pb2.ADVEncryptionType
    recipientKeyHash: bytes
    recipientTimestamp: int
    recipientKeyIndexes: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, senderKeyHash: _Optional[bytes] = ..., senderTimestamp: _Optional[int] = ..., senderKeyIndexes: _Optional[_Iterable[int]] = ..., senderAccountType: _Optional[_Union[_WAAdv_pb2.ADVEncryptionType, str]] = ..., receiverAccountType: _Optional[_Union[_WAAdv_pb2.ADVEncryptionType, str]] = ..., recipientKeyHash: _Optional[bytes] = ..., recipientTimestamp: _Optional[int] = ..., recipientKeyIndexes: _Optional[_Iterable[int]] = ...) -> None: ...

class EmbeddedMessage(_message.Message):
    __slots__ = ("stanzaID", "message")
    STANZAID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    stanzaID: str
    message: Message
    def __init__(self, stanzaID: _Optional[str] = ..., message: _Optional[_Union[Message, _Mapping]] = ...) -> None: ...

class EmbeddedMusic(_message.Message):
    __slots__ = ("musicContentMediaID", "songID", "author", "title", "artworkDirectPath", "artworkSHA256", "artworkEncSHA256", "artworkMediaKey", "artistAttribution", "countryBlocklist", "isExplicit")
    MUSICCONTENTMEDIAID_FIELD_NUMBER: _ClassVar[int]
    SONGID_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    ARTWORKDIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    ARTWORKSHA256_FIELD_NUMBER: _ClassVar[int]
    ARTWORKENCSHA256_FIELD_NUMBER: _ClassVar[int]
    ARTWORKMEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    ARTISTATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
    COUNTRYBLOCKLIST_FIELD_NUMBER: _ClassVar[int]
    ISEXPLICIT_FIELD_NUMBER: _ClassVar[int]
    musicContentMediaID: str
    songID: str
    author: str
    title: str
    artworkDirectPath: str
    artworkSHA256: bytes
    artworkEncSHA256: bytes
    artworkMediaKey: bytes
    artistAttribution: str
    countryBlocklist: bytes
    isExplicit: bool
    def __init__(self, musicContentMediaID: _Optional[str] = ..., songID: _Optional[str] = ..., author: _Optional[str] = ..., title: _Optional[str] = ..., artworkDirectPath: _Optional[str] = ..., artworkSHA256: _Optional[bytes] = ..., artworkEncSHA256: _Optional[bytes] = ..., artworkMediaKey: _Optional[bytes] = ..., artistAttribution: _Optional[str] = ..., countryBlocklist: _Optional[bytes] = ..., isExplicit: bool = ...) -> None: ...

class EmbeddedContent(_message.Message):
    __slots__ = ("embeddedMessage", "embeddedMusic")
    EMBEDDEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EMBEDDEDMUSIC_FIELD_NUMBER: _ClassVar[int]
    embeddedMessage: EmbeddedMessage
    embeddedMusic: EmbeddedMusic
    def __init__(self, embeddedMessage: _Optional[_Union[EmbeddedMessage, _Mapping]] = ..., embeddedMusic: _Optional[_Union[EmbeddedMusic, _Mapping]] = ...) -> None: ...

class TapLinkAction(_message.Message):
    __slots__ = ("title", "tapURL")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    TAPURL_FIELD_NUMBER: _ClassVar[int]
    title: str
    tapURL: str
    def __init__(self, title: _Optional[str] = ..., tapURL: _Optional[str] = ...) -> None: ...

class Point(_message.Message):
    __slots__ = ("xDeprecated", "yDeprecated", "x", "y")
    XDEPRECATED_FIELD_NUMBER: _ClassVar[int]
    YDEPRECATED_FIELD_NUMBER: _ClassVar[int]
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    xDeprecated: int
    yDeprecated: int
    x: float
    y: float
    def __init__(self, xDeprecated: _Optional[int] = ..., yDeprecated: _Optional[int] = ..., x: _Optional[float] = ..., y: _Optional[float] = ...) -> None: ...

class Location(_message.Message):
    __slots__ = ("degreesLatitude", "degreesLongitude", "name")
    DEGREESLATITUDE_FIELD_NUMBER: _ClassVar[int]
    DEGREESLONGITUDE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    degreesLatitude: float
    degreesLongitude: float
    name: str
    def __init__(self, degreesLatitude: _Optional[float] = ..., degreesLongitude: _Optional[float] = ..., name: _Optional[str] = ...) -> None: ...

class TemplateButton(_message.Message):
    __slots__ = ("quickReplyButton", "urlButton", "callButton", "index")
    class CallButton(_message.Message):
        __slots__ = ("displayText", "phoneNumber")
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
        displayText: HighlyStructuredMessage
        phoneNumber: HighlyStructuredMessage
        def __init__(self, displayText: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., phoneNumber: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ...) -> None: ...
    class URLButton(_message.Message):
        __slots__ = ("displayText", "URL")
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        URL_FIELD_NUMBER: _ClassVar[int]
        displayText: HighlyStructuredMessage
        URL: HighlyStructuredMessage
        def __init__(self, displayText: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., URL: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ...) -> None: ...
    class QuickReplyButton(_message.Message):
        __slots__ = ("displayText", "ID")
        DISPLAYTEXT_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        displayText: HighlyStructuredMessage
        ID: str
        def __init__(self, displayText: _Optional[_Union[HighlyStructuredMessage, _Mapping]] = ..., ID: _Optional[str] = ...) -> None: ...
    QUICKREPLYBUTTON_FIELD_NUMBER: _ClassVar[int]
    URLBUTTON_FIELD_NUMBER: _ClassVar[int]
    CALLBUTTON_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    quickReplyButton: TemplateButton.QuickReplyButton
    urlButton: TemplateButton.URLButton
    callButton: TemplateButton.CallButton
    index: int
    def __init__(self, quickReplyButton: _Optional[_Union[TemplateButton.QuickReplyButton, _Mapping]] = ..., urlButton: _Optional[_Union[TemplateButton.URLButton, _Mapping]] = ..., callButton: _Optional[_Union[TemplateButton.CallButton, _Mapping]] = ..., index: _Optional[int] = ...) -> None: ...

class Money(_message.Message):
    __slots__ = ("value", "offset", "currencyCode")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    CURRENCYCODE_FIELD_NUMBER: _ClassVar[int]
    value: int
    offset: int
    currencyCode: str
    def __init__(self, value: _Optional[int] = ..., offset: _Optional[int] = ..., currencyCode: _Optional[str] = ...) -> None: ...

class ActionLink(_message.Message):
    __slots__ = ("URL", "buttonTitle")
    URL_FIELD_NUMBER: _ClassVar[int]
    BUTTONTITLE_FIELD_NUMBER: _ClassVar[int]
    URL: str
    buttonTitle: str
    def __init__(self, URL: _Optional[str] = ..., buttonTitle: _Optional[str] = ...) -> None: ...

class GroupMention(_message.Message):
    __slots__ = ("groupJID", "groupSubject")
    GROUPJID_FIELD_NUMBER: _ClassVar[int]
    GROUPSUBJECT_FIELD_NUMBER: _ClassVar[int]
    groupJID: str
    groupSubject: str
    def __init__(self, groupJID: _Optional[str] = ..., groupSubject: _Optional[str] = ...) -> None: ...

class MessageSecretMessage(_message.Message):
    __slots__ = ("version", "encIV", "encPayload")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ENCIV_FIELD_NUMBER: _ClassVar[int]
    ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    version: int
    encIV: bytes
    encPayload: bytes
    def __init__(self, version: _Optional[int] = ..., encIV: _Optional[bytes] = ..., encPayload: _Optional[bytes] = ...) -> None: ...

class MediaNotifyMessage(_message.Message):
    __slots__ = ("expressPathURL", "fileEncSHA256", "fileLength")
    EXPRESSPATHURL_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    expressPathURL: str
    fileEncSHA256: bytes
    fileLength: int
    def __init__(self, expressPathURL: _Optional[str] = ..., fileEncSHA256: _Optional[bytes] = ..., fileLength: _Optional[int] = ...) -> None: ...

class LIDMigrationMappingSyncMessage(_message.Message):
    __slots__ = ("encodedMappingPayload",)
    ENCODEDMAPPINGPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    encodedMappingPayload: bytes
    def __init__(self, encodedMappingPayload: _Optional[bytes] = ...) -> None: ...

class UrlTrackingMap(_message.Message):
    __slots__ = ("urlTrackingMapElements",)
    class UrlTrackingMapElement(_message.Message):
        __slots__ = ("originalURL", "unconsentedUsersURL", "consentedUsersURL", "cardIndex")
        ORIGINALURL_FIELD_NUMBER: _ClassVar[int]
        UNCONSENTEDUSERSURL_FIELD_NUMBER: _ClassVar[int]
        CONSENTEDUSERSURL_FIELD_NUMBER: _ClassVar[int]
        CARDINDEX_FIELD_NUMBER: _ClassVar[int]
        originalURL: str
        unconsentedUsersURL: str
        consentedUsersURL: str
        cardIndex: int
        def __init__(self, originalURL: _Optional[str] = ..., unconsentedUsersURL: _Optional[str] = ..., consentedUsersURL: _Optional[str] = ..., cardIndex: _Optional[int] = ...) -> None: ...
    URLTRACKINGMAPELEMENTS_FIELD_NUMBER: _ClassVar[int]
    urlTrackingMapElements: _containers.RepeatedCompositeFieldContainer[UrlTrackingMap.UrlTrackingMapElement]
    def __init__(self, urlTrackingMapElements: _Optional[_Iterable[_Union[UrlTrackingMap.UrlTrackingMapElement, _Mapping]]] = ...) -> None: ...

class AIQueryFanout(_message.Message):
    __slots__ = ("messageKey", "message", "timestamp")
    MESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    messageKey: _WACommon_pb2.MessageKey
    message: Message
    timestamp: int
    def __init__(self, messageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., message: _Optional[_Union[Message, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class MemberLabel(_message.Message):
    __slots__ = ("label", "labelTimestamp")
    LABEL_FIELD_NUMBER: _ClassVar[int]
    LABELTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    label: str
    labelTimestamp: int
    def __init__(self, label: _Optional[str] = ..., labelTimestamp: _Optional[int] = ...) -> None: ...
