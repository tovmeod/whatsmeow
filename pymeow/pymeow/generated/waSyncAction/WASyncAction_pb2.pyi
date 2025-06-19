from waChatLockSettings import WAProtobufsChatLockSettings_pb2 as _WAProtobufsChatLockSettings_pb2
from waDeviceCapabilities import WAProtobufsDeviceCapabilities_pb2 as _WAProtobufsDeviceCapabilities_pb2
from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CallLogRecord(_message.Message):
    __slots__ = ("callResult", "isDndMode", "silenceReason", "duration", "startTime", "isIncoming", "isVideo", "isCallLink", "callLinkToken", "scheduledCallID", "callID", "callCreatorJID", "groupJID", "participants", "callType")
    class CallType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REGULAR: _ClassVar[CallLogRecord.CallType]
        SCHEDULED_CALL: _ClassVar[CallLogRecord.CallType]
        VOICE_CHAT: _ClassVar[CallLogRecord.CallType]
    REGULAR: CallLogRecord.CallType
    SCHEDULED_CALL: CallLogRecord.CallType
    VOICE_CHAT: CallLogRecord.CallType
    class SilenceReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[CallLogRecord.SilenceReason]
        SCHEDULED: _ClassVar[CallLogRecord.SilenceReason]
        PRIVACY: _ClassVar[CallLogRecord.SilenceReason]
        LIGHTWEIGHT: _ClassVar[CallLogRecord.SilenceReason]
    NONE: CallLogRecord.SilenceReason
    SCHEDULED: CallLogRecord.SilenceReason
    PRIVACY: CallLogRecord.SilenceReason
    LIGHTWEIGHT: CallLogRecord.SilenceReason
    class CallResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CONNECTED: _ClassVar[CallLogRecord.CallResult]
        REJECTED: _ClassVar[CallLogRecord.CallResult]
        CANCELLED: _ClassVar[CallLogRecord.CallResult]
        ACCEPTEDELSEWHERE: _ClassVar[CallLogRecord.CallResult]
        MISSED: _ClassVar[CallLogRecord.CallResult]
        INVALID: _ClassVar[CallLogRecord.CallResult]
        UNAVAILABLE: _ClassVar[CallLogRecord.CallResult]
        UPCOMING: _ClassVar[CallLogRecord.CallResult]
        FAILED: _ClassVar[CallLogRecord.CallResult]
        ABANDONED: _ClassVar[CallLogRecord.CallResult]
        ONGOING: _ClassVar[CallLogRecord.CallResult]
    CONNECTED: CallLogRecord.CallResult
    REJECTED: CallLogRecord.CallResult
    CANCELLED: CallLogRecord.CallResult
    ACCEPTEDELSEWHERE: CallLogRecord.CallResult
    MISSED: CallLogRecord.CallResult
    INVALID: CallLogRecord.CallResult
    UNAVAILABLE: CallLogRecord.CallResult
    UPCOMING: CallLogRecord.CallResult
    FAILED: CallLogRecord.CallResult
    ABANDONED: CallLogRecord.CallResult
    ONGOING: CallLogRecord.CallResult
    class ParticipantInfo(_message.Message):
        __slots__ = ("userJID", "callResult")
        USERJID_FIELD_NUMBER: _ClassVar[int]
        CALLRESULT_FIELD_NUMBER: _ClassVar[int]
        userJID: str
        callResult: CallLogRecord.CallResult
        def __init__(self, userJID: _Optional[str] = ..., callResult: _Optional[_Union[CallLogRecord.CallResult, str]] = ...) -> None: ...
    CALLRESULT_FIELD_NUMBER: _ClassVar[int]
    ISDNDMODE_FIELD_NUMBER: _ClassVar[int]
    SILENCEREASON_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    STARTTIME_FIELD_NUMBER: _ClassVar[int]
    ISINCOMING_FIELD_NUMBER: _ClassVar[int]
    ISVIDEO_FIELD_NUMBER: _ClassVar[int]
    ISCALLLINK_FIELD_NUMBER: _ClassVar[int]
    CALLLINKTOKEN_FIELD_NUMBER: _ClassVar[int]
    SCHEDULEDCALLID_FIELD_NUMBER: _ClassVar[int]
    CALLID_FIELD_NUMBER: _ClassVar[int]
    CALLCREATORJID_FIELD_NUMBER: _ClassVar[int]
    GROUPJID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    CALLTYPE_FIELD_NUMBER: _ClassVar[int]
    callResult: CallLogRecord.CallResult
    isDndMode: bool
    silenceReason: CallLogRecord.SilenceReason
    duration: int
    startTime: int
    isIncoming: bool
    isVideo: bool
    isCallLink: bool
    callLinkToken: str
    scheduledCallID: str
    callID: str
    callCreatorJID: str
    groupJID: str
    participants: _containers.RepeatedCompositeFieldContainer[CallLogRecord.ParticipantInfo]
    callType: CallLogRecord.CallType
    def __init__(self, callResult: _Optional[_Union[CallLogRecord.CallResult, str]] = ..., isDndMode: bool = ..., silenceReason: _Optional[_Union[CallLogRecord.SilenceReason, str]] = ..., duration: _Optional[int] = ..., startTime: _Optional[int] = ..., isIncoming: bool = ..., isVideo: bool = ..., isCallLink: bool = ..., callLinkToken: _Optional[str] = ..., scheduledCallID: _Optional[str] = ..., callID: _Optional[str] = ..., callCreatorJID: _Optional[str] = ..., groupJID: _Optional[str] = ..., participants: _Optional[_Iterable[_Union[CallLogRecord.ParticipantInfo, _Mapping]]] = ..., callType: _Optional[_Union[CallLogRecord.CallType, str]] = ...) -> None: ...

class NotificationActivitySettingAction(_message.Message):
    __slots__ = ("notificationActivitySetting",)
    class NotificationActivitySetting(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT_ALL_MESSAGES: _ClassVar[NotificationActivitySettingAction.NotificationActivitySetting]
        ALL_MESSAGES: _ClassVar[NotificationActivitySettingAction.NotificationActivitySetting]
        HIGHLIGHTS: _ClassVar[NotificationActivitySettingAction.NotificationActivitySetting]
        DEFAULT_HIGHLIGHTS: _ClassVar[NotificationActivitySettingAction.NotificationActivitySetting]
    DEFAULT_ALL_MESSAGES: NotificationActivitySettingAction.NotificationActivitySetting
    ALL_MESSAGES: NotificationActivitySettingAction.NotificationActivitySetting
    HIGHLIGHTS: NotificationActivitySettingAction.NotificationActivitySetting
    DEFAULT_HIGHLIGHTS: NotificationActivitySettingAction.NotificationActivitySetting
    NOTIFICATIONACTIVITYSETTING_FIELD_NUMBER: _ClassVar[int]
    notificationActivitySetting: NotificationActivitySettingAction.NotificationActivitySetting
    def __init__(self, notificationActivitySetting: _Optional[_Union[NotificationActivitySettingAction.NotificationActivitySetting, str]] = ...) -> None: ...

class WaffleAccountLinkStateAction(_message.Message):
    __slots__ = ("linkState",)
    class AccountLinkState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ACTIVE: _ClassVar[WaffleAccountLinkStateAction.AccountLinkState]
    ACTIVE: WaffleAccountLinkStateAction.AccountLinkState
    LINKSTATE_FIELD_NUMBER: _ClassVar[int]
    linkState: WaffleAccountLinkStateAction.AccountLinkState
    def __init__(self, linkState: _Optional[_Union[WaffleAccountLinkStateAction.AccountLinkState, str]] = ...) -> None: ...

class MerchantPaymentPartnerAction(_message.Message):
    __slots__ = ("status", "country", "gatewayName", "credentialID")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ACTIVE: _ClassVar[MerchantPaymentPartnerAction.Status]
        INACTIVE: _ClassVar[MerchantPaymentPartnerAction.Status]
    ACTIVE: MerchantPaymentPartnerAction.Status
    INACTIVE: MerchantPaymentPartnerAction.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    GATEWAYNAME_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALID_FIELD_NUMBER: _ClassVar[int]
    status: MerchantPaymentPartnerAction.Status
    country: str
    gatewayName: str
    credentialID: str
    def __init__(self, status: _Optional[_Union[MerchantPaymentPartnerAction.Status, str]] = ..., country: _Optional[str] = ..., gatewayName: _Optional[str] = ..., credentialID: _Optional[str] = ...) -> None: ...

class NoteEditAction(_message.Message):
    __slots__ = ("type", "chatJID", "createdAt", "deleted", "unstructuredContent")
    class NoteType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNSTRUCTURED: _ClassVar[NoteEditAction.NoteType]
        STRUCTURED: _ClassVar[NoteEditAction.NoteType]
    UNSTRUCTURED: NoteEditAction.NoteType
    STRUCTURED: NoteEditAction.NoteType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CHATJID_FIELD_NUMBER: _ClassVar[int]
    CREATEDAT_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    UNSTRUCTUREDCONTENT_FIELD_NUMBER: _ClassVar[int]
    type: NoteEditAction.NoteType
    chatJID: str
    createdAt: int
    deleted: bool
    unstructuredContent: str
    def __init__(self, type: _Optional[_Union[NoteEditAction.NoteType, str]] = ..., chatJID: _Optional[str] = ..., createdAt: _Optional[int] = ..., deleted: bool = ..., unstructuredContent: _Optional[str] = ...) -> None: ...

class StatusPrivacyAction(_message.Message):
    __slots__ = ("mode", "userJID")
    class StatusDistributionMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ALLOW_LIST: _ClassVar[StatusPrivacyAction.StatusDistributionMode]
        DENY_LIST: _ClassVar[StatusPrivacyAction.StatusDistributionMode]
        CONTACTS: _ClassVar[StatusPrivacyAction.StatusDistributionMode]
    ALLOW_LIST: StatusPrivacyAction.StatusDistributionMode
    DENY_LIST: StatusPrivacyAction.StatusDistributionMode
    CONTACTS: StatusPrivacyAction.StatusDistributionMode
    MODE_FIELD_NUMBER: _ClassVar[int]
    USERJID_FIELD_NUMBER: _ClassVar[int]
    mode: StatusPrivacyAction.StatusDistributionMode
    userJID: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, mode: _Optional[_Union[StatusPrivacyAction.StatusDistributionMode, str]] = ..., userJID: _Optional[_Iterable[str]] = ...) -> None: ...

class MarketingMessageAction(_message.Message):
    __slots__ = ("name", "message", "type", "createdAt", "lastSentAt", "isDeleted", "mediaID")
    class MarketingMessagePrototypeType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        PERSONALIZED: _ClassVar[MarketingMessageAction.MarketingMessagePrototypeType]
    PERSONALIZED: MarketingMessageAction.MarketingMessagePrototypeType
    NAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CREATEDAT_FIELD_NUMBER: _ClassVar[int]
    LASTSENTAT_FIELD_NUMBER: _ClassVar[int]
    ISDELETED_FIELD_NUMBER: _ClassVar[int]
    MEDIAID_FIELD_NUMBER: _ClassVar[int]
    name: str
    message: str
    type: MarketingMessageAction.MarketingMessagePrototypeType
    createdAt: int
    lastSentAt: int
    isDeleted: bool
    mediaID: str
    def __init__(self, name: _Optional[str] = ..., message: _Optional[str] = ..., type: _Optional[_Union[MarketingMessageAction.MarketingMessagePrototypeType, str]] = ..., createdAt: _Optional[int] = ..., lastSentAt: _Optional[int] = ..., isDeleted: bool = ..., mediaID: _Optional[str] = ...) -> None: ...

class UsernameChatStartModeAction(_message.Message):
    __slots__ = ("chatStartMode",)
    class ChatStartMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LID: _ClassVar[UsernameChatStartModeAction.ChatStartMode]
        PN: _ClassVar[UsernameChatStartModeAction.ChatStartMode]
    LID: UsernameChatStartModeAction.ChatStartMode
    PN: UsernameChatStartModeAction.ChatStartMode
    CHATSTARTMODE_FIELD_NUMBER: _ClassVar[int]
    chatStartMode: UsernameChatStartModeAction.ChatStartMode
    def __init__(self, chatStartMode: _Optional[_Union[UsernameChatStartModeAction.ChatStartMode, str]] = ...) -> None: ...

class LabelEditAction(_message.Message):
    __slots__ = ("name", "color", "predefinedID", "deleted", "orderIndex", "isActive", "type", "isImmutable")
    class ListType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[LabelEditAction.ListType]
        UNREAD: _ClassVar[LabelEditAction.ListType]
        GROUPS: _ClassVar[LabelEditAction.ListType]
        FAVORITES: _ClassVar[LabelEditAction.ListType]
        PREDEFINED: _ClassVar[LabelEditAction.ListType]
        CUSTOM: _ClassVar[LabelEditAction.ListType]
        COMMUNITY: _ClassVar[LabelEditAction.ListType]
        SERVER_ASSIGNED: _ClassVar[LabelEditAction.ListType]
    NONE: LabelEditAction.ListType
    UNREAD: LabelEditAction.ListType
    GROUPS: LabelEditAction.ListType
    FAVORITES: LabelEditAction.ListType
    PREDEFINED: LabelEditAction.ListType
    CUSTOM: LabelEditAction.ListType
    COMMUNITY: LabelEditAction.ListType
    SERVER_ASSIGNED: LabelEditAction.ListType
    NAME_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    PREDEFINEDID_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    ORDERINDEX_FIELD_NUMBER: _ClassVar[int]
    ISACTIVE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ISIMMUTABLE_FIELD_NUMBER: _ClassVar[int]
    name: str
    color: int
    predefinedID: int
    deleted: bool
    orderIndex: int
    isActive: bool
    type: LabelEditAction.ListType
    isImmutable: bool
    def __init__(self, name: _Optional[str] = ..., color: _Optional[int] = ..., predefinedID: _Optional[int] = ..., deleted: bool = ..., orderIndex: _Optional[int] = ..., isActive: bool = ..., type: _Optional[_Union[LabelEditAction.ListType, str]] = ..., isImmutable: bool = ...) -> None: ...

class PatchDebugData(_message.Message):
    __slots__ = ("currentLthash", "newLthash", "patchVersion", "collectionName", "firstFourBytesFromAHashOfSnapshotMACKey", "newLthashSubtract", "numberAdd", "numberRemove", "numberOverride", "senderPlatform", "isSenderPrimary")
    class Platform(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ANDROID: _ClassVar[PatchDebugData.Platform]
        SMBA: _ClassVar[PatchDebugData.Platform]
        IPHONE: _ClassVar[PatchDebugData.Platform]
        SMBI: _ClassVar[PatchDebugData.Platform]
        WEB: _ClassVar[PatchDebugData.Platform]
        UWP: _ClassVar[PatchDebugData.Platform]
        DARWIN: _ClassVar[PatchDebugData.Platform]
        IPAD: _ClassVar[PatchDebugData.Platform]
        WEAROS: _ClassVar[PatchDebugData.Platform]
    ANDROID: PatchDebugData.Platform
    SMBA: PatchDebugData.Platform
    IPHONE: PatchDebugData.Platform
    SMBI: PatchDebugData.Platform
    WEB: PatchDebugData.Platform
    UWP: PatchDebugData.Platform
    DARWIN: PatchDebugData.Platform
    IPAD: PatchDebugData.Platform
    WEAROS: PatchDebugData.Platform
    CURRENTLTHASH_FIELD_NUMBER: _ClassVar[int]
    NEWLTHASH_FIELD_NUMBER: _ClassVar[int]
    PATCHVERSION_FIELD_NUMBER: _ClassVar[int]
    COLLECTIONNAME_FIELD_NUMBER: _ClassVar[int]
    FIRSTFOURBYTESFROMAHASHOFSNAPSHOTMACKEY_FIELD_NUMBER: _ClassVar[int]
    NEWLTHASHSUBTRACT_FIELD_NUMBER: _ClassVar[int]
    NUMBERADD_FIELD_NUMBER: _ClassVar[int]
    NUMBERREMOVE_FIELD_NUMBER: _ClassVar[int]
    NUMBEROVERRIDE_FIELD_NUMBER: _ClassVar[int]
    SENDERPLATFORM_FIELD_NUMBER: _ClassVar[int]
    ISSENDERPRIMARY_FIELD_NUMBER: _ClassVar[int]
    currentLthash: bytes
    newLthash: bytes
    patchVersion: bytes
    collectionName: bytes
    firstFourBytesFromAHashOfSnapshotMACKey: bytes
    newLthashSubtract: bytes
    numberAdd: int
    numberRemove: int
    numberOverride: int
    senderPlatform: PatchDebugData.Platform
    isSenderPrimary: bool
    def __init__(self, currentLthash: _Optional[bytes] = ..., newLthash: _Optional[bytes] = ..., patchVersion: _Optional[bytes] = ..., collectionName: _Optional[bytes] = ..., firstFourBytesFromAHashOfSnapshotMACKey: _Optional[bytes] = ..., newLthashSubtract: _Optional[bytes] = ..., numberAdd: _Optional[int] = ..., numberRemove: _Optional[int] = ..., numberOverride: _Optional[int] = ..., senderPlatform: _Optional[_Union[PatchDebugData.Platform, str]] = ..., isSenderPrimary: bool = ...) -> None: ...

class RecentEmojiWeight(_message.Message):
    __slots__ = ("emoji", "weight")
    EMOJI_FIELD_NUMBER: _ClassVar[int]
    WEIGHT_FIELD_NUMBER: _ClassVar[int]
    emoji: str
    weight: float
    def __init__(self, emoji: _Optional[str] = ..., weight: _Optional[float] = ...) -> None: ...

class SyncActionValue(_message.Message):
    __slots__ = ("timestamp", "starAction", "contactAction", "muteAction", "pinAction", "securityNotificationSetting", "pushNameSetting", "quickReplyAction", "recentEmojiWeightsAction", "labelEditAction", "labelAssociationAction", "localeSetting", "archiveChatAction", "deleteMessageForMeAction", "keyExpiration", "markChatAsReadAction", "clearChatAction", "deleteChatAction", "unarchiveChatsSetting", "primaryFeature", "androidUnsupportedActions", "agentAction", "subscriptionAction", "userStatusMuteAction", "timeFormatAction", "nuxAction", "primaryVersionAction", "stickerAction", "removeRecentStickerAction", "chatAssignment", "chatAssignmentOpenedStatus", "pnForLidChatAction", "marketingMessageAction", "marketingMessageBroadcastAction", "externalWebBetaAction", "privacySettingRelayAllCalls", "callLogAction", "statusPrivacy", "botWelcomeRequestAction", "deleteIndividualCallLog", "labelReorderingAction", "paymentInfoAction", "customPaymentMethodsAction", "lockChatAction", "chatLockSettings", "wamoUserIdentifierAction", "privacySettingDisableLinkPreviewsAction", "deviceCapabilities", "noteEditAction", "favoritesAction", "merchantPaymentPartnerAction", "waffleAccountLinkStateAction", "usernameChatStartMode", "notificationActivitySettingAction", "lidContactAction", "ctwaPerCustomerDataSharingAction")
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    STARACTION_FIELD_NUMBER: _ClassVar[int]
    CONTACTACTION_FIELD_NUMBER: _ClassVar[int]
    MUTEACTION_FIELD_NUMBER: _ClassVar[int]
    PINACTION_FIELD_NUMBER: _ClassVar[int]
    SECURITYNOTIFICATIONSETTING_FIELD_NUMBER: _ClassVar[int]
    PUSHNAMESETTING_FIELD_NUMBER: _ClassVar[int]
    QUICKREPLYACTION_FIELD_NUMBER: _ClassVar[int]
    RECENTEMOJIWEIGHTSACTION_FIELD_NUMBER: _ClassVar[int]
    LABELEDITACTION_FIELD_NUMBER: _ClassVar[int]
    LABELASSOCIATIONACTION_FIELD_NUMBER: _ClassVar[int]
    LOCALESETTING_FIELD_NUMBER: _ClassVar[int]
    ARCHIVECHATACTION_FIELD_NUMBER: _ClassVar[int]
    DELETEMESSAGEFORMEACTION_FIELD_NUMBER: _ClassVar[int]
    KEYEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    MARKCHATASREADACTION_FIELD_NUMBER: _ClassVar[int]
    CLEARCHATACTION_FIELD_NUMBER: _ClassVar[int]
    DELETECHATACTION_FIELD_NUMBER: _ClassVar[int]
    UNARCHIVECHATSSETTING_FIELD_NUMBER: _ClassVar[int]
    PRIMARYFEATURE_FIELD_NUMBER: _ClassVar[int]
    ANDROIDUNSUPPORTEDACTIONS_FIELD_NUMBER: _ClassVar[int]
    AGENTACTION_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTIONACTION_FIELD_NUMBER: _ClassVar[int]
    USERSTATUSMUTEACTION_FIELD_NUMBER: _ClassVar[int]
    TIMEFORMATACTION_FIELD_NUMBER: _ClassVar[int]
    NUXACTION_FIELD_NUMBER: _ClassVar[int]
    PRIMARYVERSIONACTION_FIELD_NUMBER: _ClassVar[int]
    STICKERACTION_FIELD_NUMBER: _ClassVar[int]
    REMOVERECENTSTICKERACTION_FIELD_NUMBER: _ClassVar[int]
    CHATASSIGNMENT_FIELD_NUMBER: _ClassVar[int]
    CHATASSIGNMENTOPENEDSTATUS_FIELD_NUMBER: _ClassVar[int]
    PNFORLIDCHATACTION_FIELD_NUMBER: _ClassVar[int]
    MARKETINGMESSAGEACTION_FIELD_NUMBER: _ClassVar[int]
    MARKETINGMESSAGEBROADCASTACTION_FIELD_NUMBER: _ClassVar[int]
    EXTERNALWEBBETAACTION_FIELD_NUMBER: _ClassVar[int]
    PRIVACYSETTINGRELAYALLCALLS_FIELD_NUMBER: _ClassVar[int]
    CALLLOGACTION_FIELD_NUMBER: _ClassVar[int]
    STATUSPRIVACY_FIELD_NUMBER: _ClassVar[int]
    BOTWELCOMEREQUESTACTION_FIELD_NUMBER: _ClassVar[int]
    DELETEINDIVIDUALCALLLOG_FIELD_NUMBER: _ClassVar[int]
    LABELREORDERINGACTION_FIELD_NUMBER: _ClassVar[int]
    PAYMENTINFOACTION_FIELD_NUMBER: _ClassVar[int]
    CUSTOMPAYMENTMETHODSACTION_FIELD_NUMBER: _ClassVar[int]
    LOCKCHATACTION_FIELD_NUMBER: _ClassVar[int]
    CHATLOCKSETTINGS_FIELD_NUMBER: _ClassVar[int]
    WAMOUSERIDENTIFIERACTION_FIELD_NUMBER: _ClassVar[int]
    PRIVACYSETTINGDISABLELINKPREVIEWSACTION_FIELD_NUMBER: _ClassVar[int]
    DEVICECAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    NOTEEDITACTION_FIELD_NUMBER: _ClassVar[int]
    FAVORITESACTION_FIELD_NUMBER: _ClassVar[int]
    MERCHANTPAYMENTPARTNERACTION_FIELD_NUMBER: _ClassVar[int]
    WAFFLEACCOUNTLINKSTATEACTION_FIELD_NUMBER: _ClassVar[int]
    USERNAMECHATSTARTMODE_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATIONACTIVITYSETTINGACTION_FIELD_NUMBER: _ClassVar[int]
    LIDCONTACTACTION_FIELD_NUMBER: _ClassVar[int]
    CTWAPERCUSTOMERDATASHARINGACTION_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    starAction: StarAction
    contactAction: ContactAction
    muteAction: MuteAction
    pinAction: PinAction
    securityNotificationSetting: SecurityNotificationSetting
    pushNameSetting: PushNameSetting
    quickReplyAction: QuickReplyAction
    recentEmojiWeightsAction: RecentEmojiWeightsAction
    labelEditAction: LabelEditAction
    labelAssociationAction: LabelAssociationAction
    localeSetting: LocaleSetting
    archiveChatAction: ArchiveChatAction
    deleteMessageForMeAction: DeleteMessageForMeAction
    keyExpiration: KeyExpiration
    markChatAsReadAction: MarkChatAsReadAction
    clearChatAction: ClearChatAction
    deleteChatAction: DeleteChatAction
    unarchiveChatsSetting: UnarchiveChatsSetting
    primaryFeature: PrimaryFeature
    androidUnsupportedActions: AndroidUnsupportedActions
    agentAction: AgentAction
    subscriptionAction: SubscriptionAction
    userStatusMuteAction: UserStatusMuteAction
    timeFormatAction: TimeFormatAction
    nuxAction: NuxAction
    primaryVersionAction: PrimaryVersionAction
    stickerAction: StickerAction
    removeRecentStickerAction: RemoveRecentStickerAction
    chatAssignment: ChatAssignmentAction
    chatAssignmentOpenedStatus: ChatAssignmentOpenedStatusAction
    pnForLidChatAction: PnForLidChatAction
    marketingMessageAction: MarketingMessageAction
    marketingMessageBroadcastAction: MarketingMessageBroadcastAction
    externalWebBetaAction: ExternalWebBetaAction
    privacySettingRelayAllCalls: PrivacySettingRelayAllCalls
    callLogAction: CallLogAction
    statusPrivacy: StatusPrivacyAction
    botWelcomeRequestAction: BotWelcomeRequestAction
    deleteIndividualCallLog: DeleteIndividualCallLogAction
    labelReorderingAction: LabelReorderingAction
    paymentInfoAction: PaymentInfoAction
    customPaymentMethodsAction: CustomPaymentMethodsAction
    lockChatAction: LockChatAction
    chatLockSettings: _WAProtobufsChatLockSettings_pb2.ChatLockSettings
    wamoUserIdentifierAction: WamoUserIdentifierAction
    privacySettingDisableLinkPreviewsAction: PrivacySettingDisableLinkPreviewsAction
    deviceCapabilities: _WAProtobufsDeviceCapabilities_pb2.DeviceCapabilities
    noteEditAction: NoteEditAction
    favoritesAction: FavoritesAction
    merchantPaymentPartnerAction: MerchantPaymentPartnerAction
    waffleAccountLinkStateAction: WaffleAccountLinkStateAction
    usernameChatStartMode: UsernameChatStartModeAction
    notificationActivitySettingAction: NotificationActivitySettingAction
    lidContactAction: LidContactAction
    ctwaPerCustomerDataSharingAction: CtwaPerCustomerDataSharingAction
    def __init__(self, timestamp: _Optional[int] = ..., starAction: _Optional[_Union[StarAction, _Mapping]] = ..., contactAction: _Optional[_Union[ContactAction, _Mapping]] = ..., muteAction: _Optional[_Union[MuteAction, _Mapping]] = ..., pinAction: _Optional[_Union[PinAction, _Mapping]] = ..., securityNotificationSetting: _Optional[_Union[SecurityNotificationSetting, _Mapping]] = ..., pushNameSetting: _Optional[_Union[PushNameSetting, _Mapping]] = ..., quickReplyAction: _Optional[_Union[QuickReplyAction, _Mapping]] = ..., recentEmojiWeightsAction: _Optional[_Union[RecentEmojiWeightsAction, _Mapping]] = ..., labelEditAction: _Optional[_Union[LabelEditAction, _Mapping]] = ..., labelAssociationAction: _Optional[_Union[LabelAssociationAction, _Mapping]] = ..., localeSetting: _Optional[_Union[LocaleSetting, _Mapping]] = ..., archiveChatAction: _Optional[_Union[ArchiveChatAction, _Mapping]] = ..., deleteMessageForMeAction: _Optional[_Union[DeleteMessageForMeAction, _Mapping]] = ..., keyExpiration: _Optional[_Union[KeyExpiration, _Mapping]] = ..., markChatAsReadAction: _Optional[_Union[MarkChatAsReadAction, _Mapping]] = ..., clearChatAction: _Optional[_Union[ClearChatAction, _Mapping]] = ..., deleteChatAction: _Optional[_Union[DeleteChatAction, _Mapping]] = ..., unarchiveChatsSetting: _Optional[_Union[UnarchiveChatsSetting, _Mapping]] = ..., primaryFeature: _Optional[_Union[PrimaryFeature, _Mapping]] = ..., androidUnsupportedActions: _Optional[_Union[AndroidUnsupportedActions, _Mapping]] = ..., agentAction: _Optional[_Union[AgentAction, _Mapping]] = ..., subscriptionAction: _Optional[_Union[SubscriptionAction, _Mapping]] = ..., userStatusMuteAction: _Optional[_Union[UserStatusMuteAction, _Mapping]] = ..., timeFormatAction: _Optional[_Union[TimeFormatAction, _Mapping]] = ..., nuxAction: _Optional[_Union[NuxAction, _Mapping]] = ..., primaryVersionAction: _Optional[_Union[PrimaryVersionAction, _Mapping]] = ..., stickerAction: _Optional[_Union[StickerAction, _Mapping]] = ..., removeRecentStickerAction: _Optional[_Union[RemoveRecentStickerAction, _Mapping]] = ..., chatAssignment: _Optional[_Union[ChatAssignmentAction, _Mapping]] = ..., chatAssignmentOpenedStatus: _Optional[_Union[ChatAssignmentOpenedStatusAction, _Mapping]] = ..., pnForLidChatAction: _Optional[_Union[PnForLidChatAction, _Mapping]] = ..., marketingMessageAction: _Optional[_Union[MarketingMessageAction, _Mapping]] = ..., marketingMessageBroadcastAction: _Optional[_Union[MarketingMessageBroadcastAction, _Mapping]] = ..., externalWebBetaAction: _Optional[_Union[ExternalWebBetaAction, _Mapping]] = ..., privacySettingRelayAllCalls: _Optional[_Union[PrivacySettingRelayAllCalls, _Mapping]] = ..., callLogAction: _Optional[_Union[CallLogAction, _Mapping]] = ..., statusPrivacy: _Optional[_Union[StatusPrivacyAction, _Mapping]] = ..., botWelcomeRequestAction: _Optional[_Union[BotWelcomeRequestAction, _Mapping]] = ..., deleteIndividualCallLog: _Optional[_Union[DeleteIndividualCallLogAction, _Mapping]] = ..., labelReorderingAction: _Optional[_Union[LabelReorderingAction, _Mapping]] = ..., paymentInfoAction: _Optional[_Union[PaymentInfoAction, _Mapping]] = ..., customPaymentMethodsAction: _Optional[_Union[CustomPaymentMethodsAction, _Mapping]] = ..., lockChatAction: _Optional[_Union[LockChatAction, _Mapping]] = ..., chatLockSettings: _Optional[_Union[_WAProtobufsChatLockSettings_pb2.ChatLockSettings, _Mapping]] = ..., wamoUserIdentifierAction: _Optional[_Union[WamoUserIdentifierAction, _Mapping]] = ..., privacySettingDisableLinkPreviewsAction: _Optional[_Union[PrivacySettingDisableLinkPreviewsAction, _Mapping]] = ..., deviceCapabilities: _Optional[_Union[_WAProtobufsDeviceCapabilities_pb2.DeviceCapabilities, _Mapping]] = ..., noteEditAction: _Optional[_Union[NoteEditAction, _Mapping]] = ..., favoritesAction: _Optional[_Union[FavoritesAction, _Mapping]] = ..., merchantPaymentPartnerAction: _Optional[_Union[MerchantPaymentPartnerAction, _Mapping]] = ..., waffleAccountLinkStateAction: _Optional[_Union[WaffleAccountLinkStateAction, _Mapping]] = ..., usernameChatStartMode: _Optional[_Union[UsernameChatStartModeAction, _Mapping]] = ..., notificationActivitySettingAction: _Optional[_Union[NotificationActivitySettingAction, _Mapping]] = ..., lidContactAction: _Optional[_Union[LidContactAction, _Mapping]] = ..., ctwaPerCustomerDataSharingAction: _Optional[_Union[CtwaPerCustomerDataSharingAction, _Mapping]] = ...) -> None: ...

class CtwaPerCustomerDataSharingAction(_message.Message):
    __slots__ = ("isCtwaPerCustomerDataSharingEnabled",)
    ISCTWAPERCUSTOMERDATASHARINGENABLED_FIELD_NUMBER: _ClassVar[int]
    isCtwaPerCustomerDataSharingEnabled: bool
    def __init__(self, isCtwaPerCustomerDataSharingEnabled: bool = ...) -> None: ...

class LidContactAction(_message.Message):
    __slots__ = ("fullName", "firstName", "username", "saveOnPrimaryAddressbook")
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    FIRSTNAME_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    SAVEONPRIMARYADDRESSBOOK_FIELD_NUMBER: _ClassVar[int]
    fullName: str
    firstName: str
    username: str
    saveOnPrimaryAddressbook: bool
    def __init__(self, fullName: _Optional[str] = ..., firstName: _Optional[str] = ..., username: _Optional[str] = ..., saveOnPrimaryAddressbook: bool = ...) -> None: ...

class FavoritesAction(_message.Message):
    __slots__ = ("favorites",)
    class Favorite(_message.Message):
        __slots__ = ("ID",)
        ID_FIELD_NUMBER: _ClassVar[int]
        ID: str
        def __init__(self, ID: _Optional[str] = ...) -> None: ...
    FAVORITES_FIELD_NUMBER: _ClassVar[int]
    favorites: _containers.RepeatedCompositeFieldContainer[FavoritesAction.Favorite]
    def __init__(self, favorites: _Optional[_Iterable[_Union[FavoritesAction.Favorite, _Mapping]]] = ...) -> None: ...

class PrivacySettingDisableLinkPreviewsAction(_message.Message):
    __slots__ = ("isPreviewsDisabled",)
    ISPREVIEWSDISABLED_FIELD_NUMBER: _ClassVar[int]
    isPreviewsDisabled: bool
    def __init__(self, isPreviewsDisabled: bool = ...) -> None: ...

class WamoUserIdentifierAction(_message.Message):
    __slots__ = ("identifier",)
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    def __init__(self, identifier: _Optional[str] = ...) -> None: ...

class LockChatAction(_message.Message):
    __slots__ = ("locked",)
    LOCKED_FIELD_NUMBER: _ClassVar[int]
    locked: bool
    def __init__(self, locked: bool = ...) -> None: ...

class CustomPaymentMethodsAction(_message.Message):
    __slots__ = ("customPaymentMethods",)
    CUSTOMPAYMENTMETHODS_FIELD_NUMBER: _ClassVar[int]
    customPaymentMethods: _containers.RepeatedCompositeFieldContainer[CustomPaymentMethod]
    def __init__(self, customPaymentMethods: _Optional[_Iterable[_Union[CustomPaymentMethod, _Mapping]]] = ...) -> None: ...

class CustomPaymentMethod(_message.Message):
    __slots__ = ("credentialID", "country", "type", "metadata")
    CREDENTIALID_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    credentialID: str
    country: str
    type: str
    metadata: _containers.RepeatedCompositeFieldContainer[CustomPaymentMethodMetadata]
    def __init__(self, credentialID: _Optional[str] = ..., country: _Optional[str] = ..., type: _Optional[str] = ..., metadata: _Optional[_Iterable[_Union[CustomPaymentMethodMetadata, _Mapping]]] = ...) -> None: ...

class CustomPaymentMethodMetadata(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class PaymentInfoAction(_message.Message):
    __slots__ = ("cpi",)
    CPI_FIELD_NUMBER: _ClassVar[int]
    cpi: str
    def __init__(self, cpi: _Optional[str] = ...) -> None: ...

class LabelReorderingAction(_message.Message):
    __slots__ = ("sortedLabelIDs",)
    SORTEDLABELIDS_FIELD_NUMBER: _ClassVar[int]
    sortedLabelIDs: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, sortedLabelIDs: _Optional[_Iterable[int]] = ...) -> None: ...

class DeleteIndividualCallLogAction(_message.Message):
    __slots__ = ("peerJID", "isIncoming")
    PEERJID_FIELD_NUMBER: _ClassVar[int]
    ISINCOMING_FIELD_NUMBER: _ClassVar[int]
    peerJID: str
    isIncoming: bool
    def __init__(self, peerJID: _Optional[str] = ..., isIncoming: bool = ...) -> None: ...

class BotWelcomeRequestAction(_message.Message):
    __slots__ = ("isSent",)
    ISSENT_FIELD_NUMBER: _ClassVar[int]
    isSent: bool
    def __init__(self, isSent: bool = ...) -> None: ...

class CallLogAction(_message.Message):
    __slots__ = ("callLogRecord",)
    CALLLOGRECORD_FIELD_NUMBER: _ClassVar[int]
    callLogRecord: CallLogRecord
    def __init__(self, callLogRecord: _Optional[_Union[CallLogRecord, _Mapping]] = ...) -> None: ...

class PrivacySettingRelayAllCalls(_message.Message):
    __slots__ = ("isEnabled",)
    ISENABLED_FIELD_NUMBER: _ClassVar[int]
    isEnabled: bool
    def __init__(self, isEnabled: bool = ...) -> None: ...

class ExternalWebBetaAction(_message.Message):
    __slots__ = ("isOptIn",)
    ISOPTIN_FIELD_NUMBER: _ClassVar[int]
    isOptIn: bool
    def __init__(self, isOptIn: bool = ...) -> None: ...

class MarketingMessageBroadcastAction(_message.Message):
    __slots__ = ("repliedCount",)
    REPLIEDCOUNT_FIELD_NUMBER: _ClassVar[int]
    repliedCount: int
    def __init__(self, repliedCount: _Optional[int] = ...) -> None: ...

class PnForLidChatAction(_message.Message):
    __slots__ = ("pnJID",)
    PNJID_FIELD_NUMBER: _ClassVar[int]
    pnJID: str
    def __init__(self, pnJID: _Optional[str] = ...) -> None: ...

class ChatAssignmentOpenedStatusAction(_message.Message):
    __slots__ = ("chatOpened",)
    CHATOPENED_FIELD_NUMBER: _ClassVar[int]
    chatOpened: bool
    def __init__(self, chatOpened: bool = ...) -> None: ...

class ChatAssignmentAction(_message.Message):
    __slots__ = ("deviceAgentID",)
    DEVICEAGENTID_FIELD_NUMBER: _ClassVar[int]
    deviceAgentID: str
    def __init__(self, deviceAgentID: _Optional[str] = ...) -> None: ...

class StickerAction(_message.Message):
    __slots__ = ("URL", "fileEncSHA256", "mediaKey", "mimetype", "height", "width", "directPath", "fileLength", "isFavorite", "deviceIDHint", "isLottie")
    URL_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    MIMETYPE_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    FILELENGTH_FIELD_NUMBER: _ClassVar[int]
    ISFAVORITE_FIELD_NUMBER: _ClassVar[int]
    DEVICEIDHINT_FIELD_NUMBER: _ClassVar[int]
    ISLOTTIE_FIELD_NUMBER: _ClassVar[int]
    URL: str
    fileEncSHA256: bytes
    mediaKey: bytes
    mimetype: str
    height: int
    width: int
    directPath: str
    fileLength: int
    isFavorite: bool
    deviceIDHint: int
    isLottie: bool
    def __init__(self, URL: _Optional[str] = ..., fileEncSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., mimetype: _Optional[str] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., directPath: _Optional[str] = ..., fileLength: _Optional[int] = ..., isFavorite: bool = ..., deviceIDHint: _Optional[int] = ..., isLottie: bool = ...) -> None: ...

class RemoveRecentStickerAction(_message.Message):
    __slots__ = ("lastStickerSentTS",)
    LASTSTICKERSENTTS_FIELD_NUMBER: _ClassVar[int]
    lastStickerSentTS: int
    def __init__(self, lastStickerSentTS: _Optional[int] = ...) -> None: ...

class PrimaryVersionAction(_message.Message):
    __slots__ = ("version",)
    VERSION_FIELD_NUMBER: _ClassVar[int]
    version: str
    def __init__(self, version: _Optional[str] = ...) -> None: ...

class NuxAction(_message.Message):
    __slots__ = ("acknowledged",)
    ACKNOWLEDGED_FIELD_NUMBER: _ClassVar[int]
    acknowledged: bool
    def __init__(self, acknowledged: bool = ...) -> None: ...

class TimeFormatAction(_message.Message):
    __slots__ = ("isTwentyFourHourFormatEnabled",)
    ISTWENTYFOURHOURFORMATENABLED_FIELD_NUMBER: _ClassVar[int]
    isTwentyFourHourFormatEnabled: bool
    def __init__(self, isTwentyFourHourFormatEnabled: bool = ...) -> None: ...

class UserStatusMuteAction(_message.Message):
    __slots__ = ("muted",)
    MUTED_FIELD_NUMBER: _ClassVar[int]
    muted: bool
    def __init__(self, muted: bool = ...) -> None: ...

class SubscriptionAction(_message.Message):
    __slots__ = ("isDeactivated", "isAutoRenewing", "expirationDate")
    ISDEACTIVATED_FIELD_NUMBER: _ClassVar[int]
    ISAUTORENEWING_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONDATE_FIELD_NUMBER: _ClassVar[int]
    isDeactivated: bool
    isAutoRenewing: bool
    expirationDate: int
    def __init__(self, isDeactivated: bool = ..., isAutoRenewing: bool = ..., expirationDate: _Optional[int] = ...) -> None: ...

class AgentAction(_message.Message):
    __slots__ = ("name", "deviceID", "isDeleted")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    ISDELETED_FIELD_NUMBER: _ClassVar[int]
    name: str
    deviceID: int
    isDeleted: bool
    def __init__(self, name: _Optional[str] = ..., deviceID: _Optional[int] = ..., isDeleted: bool = ...) -> None: ...

class AndroidUnsupportedActions(_message.Message):
    __slots__ = ("allowed",)
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    allowed: bool
    def __init__(self, allowed: bool = ...) -> None: ...

class PrimaryFeature(_message.Message):
    __slots__ = ("flags",)
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    flags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, flags: _Optional[_Iterable[str]] = ...) -> None: ...

class KeyExpiration(_message.Message):
    __slots__ = ("expiredKeyEpoch",)
    EXPIREDKEYEPOCH_FIELD_NUMBER: _ClassVar[int]
    expiredKeyEpoch: int
    def __init__(self, expiredKeyEpoch: _Optional[int] = ...) -> None: ...

class SyncActionMessage(_message.Message):
    __slots__ = ("key", "timestamp")
    KEY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    key: _WACommon_pb2.MessageKey
    timestamp: int
    def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...

class SyncActionMessageRange(_message.Message):
    __slots__ = ("lastMessageTimestamp", "lastSystemMessageTimestamp", "messages")
    LASTMESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    LASTSYSTEMMESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    lastMessageTimestamp: int
    lastSystemMessageTimestamp: int
    messages: _containers.RepeatedCompositeFieldContainer[SyncActionMessage]
    def __init__(self, lastMessageTimestamp: _Optional[int] = ..., lastSystemMessageTimestamp: _Optional[int] = ..., messages: _Optional[_Iterable[_Union[SyncActionMessage, _Mapping]]] = ...) -> None: ...

class UnarchiveChatsSetting(_message.Message):
    __slots__ = ("unarchiveChats",)
    UNARCHIVECHATS_FIELD_NUMBER: _ClassVar[int]
    unarchiveChats: bool
    def __init__(self, unarchiveChats: bool = ...) -> None: ...

class DeleteChatAction(_message.Message):
    __slots__ = ("messageRange",)
    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
    messageRange: SyncActionMessageRange
    def __init__(self, messageRange: _Optional[_Union[SyncActionMessageRange, _Mapping]] = ...) -> None: ...

class ClearChatAction(_message.Message):
    __slots__ = ("messageRange",)
    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
    messageRange: SyncActionMessageRange
    def __init__(self, messageRange: _Optional[_Union[SyncActionMessageRange, _Mapping]] = ...) -> None: ...

class MarkChatAsReadAction(_message.Message):
    __slots__ = ("read", "messageRange")
    READ_FIELD_NUMBER: _ClassVar[int]
    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
    read: bool
    messageRange: SyncActionMessageRange
    def __init__(self, read: bool = ..., messageRange: _Optional[_Union[SyncActionMessageRange, _Mapping]] = ...) -> None: ...

class DeleteMessageForMeAction(_message.Message):
    __slots__ = ("deleteMedia", "messageTimestamp")
    DELETEMEDIA_FIELD_NUMBER: _ClassVar[int]
    MESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    deleteMedia: bool
    messageTimestamp: int
    def __init__(self, deleteMedia: bool = ..., messageTimestamp: _Optional[int] = ...) -> None: ...

class ArchiveChatAction(_message.Message):
    __slots__ = ("archived", "messageRange")
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
    archived: bool
    messageRange: SyncActionMessageRange
    def __init__(self, archived: bool = ..., messageRange: _Optional[_Union[SyncActionMessageRange, _Mapping]] = ...) -> None: ...

class RecentEmojiWeightsAction(_message.Message):
    __slots__ = ("weights",)
    WEIGHTS_FIELD_NUMBER: _ClassVar[int]
    weights: _containers.RepeatedCompositeFieldContainer[RecentEmojiWeight]
    def __init__(self, weights: _Optional[_Iterable[_Union[RecentEmojiWeight, _Mapping]]] = ...) -> None: ...

class LabelAssociationAction(_message.Message):
    __slots__ = ("labeled",)
    LABELED_FIELD_NUMBER: _ClassVar[int]
    labeled: bool
    def __init__(self, labeled: bool = ...) -> None: ...

class QuickReplyAction(_message.Message):
    __slots__ = ("shortcut", "message", "keywords", "count", "deleted")
    SHORTCUT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    KEYWORDS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    shortcut: str
    message: str
    keywords: _containers.RepeatedScalarFieldContainer[str]
    count: int
    deleted: bool
    def __init__(self, shortcut: _Optional[str] = ..., message: _Optional[str] = ..., keywords: _Optional[_Iterable[str]] = ..., count: _Optional[int] = ..., deleted: bool = ...) -> None: ...

class LocaleSetting(_message.Message):
    __slots__ = ("locale",)
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    locale: str
    def __init__(self, locale: _Optional[str] = ...) -> None: ...

class PushNameSetting(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class SecurityNotificationSetting(_message.Message):
    __slots__ = ("showNotification",)
    SHOWNOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    showNotification: bool
    def __init__(self, showNotification: bool = ...) -> None: ...

class PinAction(_message.Message):
    __slots__ = ("pinned",)
    PINNED_FIELD_NUMBER: _ClassVar[int]
    pinned: bool
    def __init__(self, pinned: bool = ...) -> None: ...

class MuteAction(_message.Message):
    __slots__ = ("muted", "muteEndTimestamp", "autoMuted")
    MUTED_FIELD_NUMBER: _ClassVar[int]
    MUTEENDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    AUTOMUTED_FIELD_NUMBER: _ClassVar[int]
    muted: bool
    muteEndTimestamp: int
    autoMuted: bool
    def __init__(self, muted: bool = ..., muteEndTimestamp: _Optional[int] = ..., autoMuted: bool = ...) -> None: ...

class ContactAction(_message.Message):
    __slots__ = ("fullName", "firstName", "lidJID", "saveOnPrimaryAddressbook", "pnJID", "username")
    FULLNAME_FIELD_NUMBER: _ClassVar[int]
    FIRSTNAME_FIELD_NUMBER: _ClassVar[int]
    LIDJID_FIELD_NUMBER: _ClassVar[int]
    SAVEONPRIMARYADDRESSBOOK_FIELD_NUMBER: _ClassVar[int]
    PNJID_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    fullName: str
    firstName: str
    lidJID: str
    saveOnPrimaryAddressbook: bool
    pnJID: str
    username: str
    def __init__(self, fullName: _Optional[str] = ..., firstName: _Optional[str] = ..., lidJID: _Optional[str] = ..., saveOnPrimaryAddressbook: bool = ..., pnJID: _Optional[str] = ..., username: _Optional[str] = ...) -> None: ...

class StarAction(_message.Message):
    __slots__ = ("starred",)
    STARRED_FIELD_NUMBER: _ClassVar[int]
    starred: bool
    def __init__(self, starred: bool = ...) -> None: ...

class SyncActionData(_message.Message):
    __slots__ = ("index", "value", "padding", "version")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    PADDING_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    index: bytes
    value: SyncActionValue
    padding: bytes
    version: int
    def __init__(self, index: _Optional[bytes] = ..., value: _Optional[_Union[SyncActionValue, _Mapping]] = ..., padding: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...
