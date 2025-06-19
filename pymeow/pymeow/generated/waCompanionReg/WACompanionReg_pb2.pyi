from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DeviceProps(_message.Message):
    __slots__ = ("os", "version", "platformType", "requireFullSync", "historySyncConfig")
    class PlatformType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[DeviceProps.PlatformType]
        CHROME: _ClassVar[DeviceProps.PlatformType]
        FIREFOX: _ClassVar[DeviceProps.PlatformType]
        IE: _ClassVar[DeviceProps.PlatformType]
        OPERA: _ClassVar[DeviceProps.PlatformType]
        SAFARI: _ClassVar[DeviceProps.PlatformType]
        EDGE: _ClassVar[DeviceProps.PlatformType]
        DESKTOP: _ClassVar[DeviceProps.PlatformType]
        IPAD: _ClassVar[DeviceProps.PlatformType]
        ANDROID_TABLET: _ClassVar[DeviceProps.PlatformType]
        OHANA: _ClassVar[DeviceProps.PlatformType]
        ALOHA: _ClassVar[DeviceProps.PlatformType]
        CATALINA: _ClassVar[DeviceProps.PlatformType]
        TCL_TV: _ClassVar[DeviceProps.PlatformType]
        IOS_PHONE: _ClassVar[DeviceProps.PlatformType]
        IOS_CATALYST: _ClassVar[DeviceProps.PlatformType]
        ANDROID_PHONE: _ClassVar[DeviceProps.PlatformType]
        ANDROID_AMBIGUOUS: _ClassVar[DeviceProps.PlatformType]
        WEAR_OS: _ClassVar[DeviceProps.PlatformType]
        AR_WRIST: _ClassVar[DeviceProps.PlatformType]
        AR_DEVICE: _ClassVar[DeviceProps.PlatformType]
        UWP: _ClassVar[DeviceProps.PlatformType]
        VR: _ClassVar[DeviceProps.PlatformType]
        CLOUD_API: _ClassVar[DeviceProps.PlatformType]
        SMARTGLASSES: _ClassVar[DeviceProps.PlatformType]
    UNKNOWN: DeviceProps.PlatformType
    CHROME: DeviceProps.PlatformType
    FIREFOX: DeviceProps.PlatformType
    IE: DeviceProps.PlatformType
    OPERA: DeviceProps.PlatformType
    SAFARI: DeviceProps.PlatformType
    EDGE: DeviceProps.PlatformType
    DESKTOP: DeviceProps.PlatformType
    IPAD: DeviceProps.PlatformType
    ANDROID_TABLET: DeviceProps.PlatformType
    OHANA: DeviceProps.PlatformType
    ALOHA: DeviceProps.PlatformType
    CATALINA: DeviceProps.PlatformType
    TCL_TV: DeviceProps.PlatformType
    IOS_PHONE: DeviceProps.PlatformType
    IOS_CATALYST: DeviceProps.PlatformType
    ANDROID_PHONE: DeviceProps.PlatformType
    ANDROID_AMBIGUOUS: DeviceProps.PlatformType
    WEAR_OS: DeviceProps.PlatformType
    AR_WRIST: DeviceProps.PlatformType
    AR_DEVICE: DeviceProps.PlatformType
    UWP: DeviceProps.PlatformType
    VR: DeviceProps.PlatformType
    CLOUD_API: DeviceProps.PlatformType
    SMARTGLASSES: DeviceProps.PlatformType
    class HistorySyncConfig(_message.Message):
        __slots__ = ("fullSyncDaysLimit", "fullSyncSizeMbLimit", "storageQuotaMb", "inlineInitialPayloadInE2EeMsg", "recentSyncDaysLimit", "supportCallLogHistory", "supportBotUserAgentChatHistory", "supportCagReactionsAndPolls", "supportBizHostedMsg", "supportRecentSyncChunkMessageCountTuning", "supportHostedGroupMsg", "supportFbidBotChatHistory", "supportAddOnHistorySyncMigration", "supportMessageAssociation")
        FULLSYNCDAYSLIMIT_FIELD_NUMBER: _ClassVar[int]
        FULLSYNCSIZEMBLIMIT_FIELD_NUMBER: _ClassVar[int]
        STORAGEQUOTAMB_FIELD_NUMBER: _ClassVar[int]
        INLINEINITIALPAYLOADINE2EEMSG_FIELD_NUMBER: _ClassVar[int]
        RECENTSYNCDAYSLIMIT_FIELD_NUMBER: _ClassVar[int]
        SUPPORTCALLLOGHISTORY_FIELD_NUMBER: _ClassVar[int]
        SUPPORTBOTUSERAGENTCHATHISTORY_FIELD_NUMBER: _ClassVar[int]
        SUPPORTCAGREACTIONSANDPOLLS_FIELD_NUMBER: _ClassVar[int]
        SUPPORTBIZHOSTEDMSG_FIELD_NUMBER: _ClassVar[int]
        SUPPORTRECENTSYNCCHUNKMESSAGECOUNTTUNING_FIELD_NUMBER: _ClassVar[int]
        SUPPORTHOSTEDGROUPMSG_FIELD_NUMBER: _ClassVar[int]
        SUPPORTFBIDBOTCHATHISTORY_FIELD_NUMBER: _ClassVar[int]
        SUPPORTADDONHISTORYSYNCMIGRATION_FIELD_NUMBER: _ClassVar[int]
        SUPPORTMESSAGEASSOCIATION_FIELD_NUMBER: _ClassVar[int]
        fullSyncDaysLimit: int
        fullSyncSizeMbLimit: int
        storageQuotaMb: int
        inlineInitialPayloadInE2EeMsg: bool
        recentSyncDaysLimit: int
        supportCallLogHistory: bool
        supportBotUserAgentChatHistory: bool
        supportCagReactionsAndPolls: bool
        supportBizHostedMsg: bool
        supportRecentSyncChunkMessageCountTuning: bool
        supportHostedGroupMsg: bool
        supportFbidBotChatHistory: bool
        supportAddOnHistorySyncMigration: bool
        supportMessageAssociation: bool
        def __init__(self, fullSyncDaysLimit: _Optional[int] = ..., fullSyncSizeMbLimit: _Optional[int] = ..., storageQuotaMb: _Optional[int] = ..., inlineInitialPayloadInE2EeMsg: bool = ..., recentSyncDaysLimit: _Optional[int] = ..., supportCallLogHistory: bool = ..., supportBotUserAgentChatHistory: bool = ..., supportCagReactionsAndPolls: bool = ..., supportBizHostedMsg: bool = ..., supportRecentSyncChunkMessageCountTuning: bool = ..., supportHostedGroupMsg: bool = ..., supportFbidBotChatHistory: bool = ..., supportAddOnHistorySyncMigration: bool = ..., supportMessageAssociation: bool = ...) -> None: ...
    class AppVersion(_message.Message):
        __slots__ = ("primary", "secondary", "tertiary", "quaternary", "quinary")
        PRIMARY_FIELD_NUMBER: _ClassVar[int]
        SECONDARY_FIELD_NUMBER: _ClassVar[int]
        TERTIARY_FIELD_NUMBER: _ClassVar[int]
        QUATERNARY_FIELD_NUMBER: _ClassVar[int]
        QUINARY_FIELD_NUMBER: _ClassVar[int]
        primary: int
        secondary: int
        tertiary: int
        quaternary: int
        quinary: int
        def __init__(self, primary: _Optional[int] = ..., secondary: _Optional[int] = ..., tertiary: _Optional[int] = ..., quaternary: _Optional[int] = ..., quinary: _Optional[int] = ...) -> None: ...
    OS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PLATFORMTYPE_FIELD_NUMBER: _ClassVar[int]
    REQUIREFULLSYNC_FIELD_NUMBER: _ClassVar[int]
    HISTORYSYNCCONFIG_FIELD_NUMBER: _ClassVar[int]
    os: str
    version: DeviceProps.AppVersion
    platformType: DeviceProps.PlatformType
    requireFullSync: bool
    historySyncConfig: DeviceProps.HistorySyncConfig
    def __init__(self, os: _Optional[str] = ..., version: _Optional[_Union[DeviceProps.AppVersion, _Mapping]] = ..., platformType: _Optional[_Union[DeviceProps.PlatformType, str]] = ..., requireFullSync: bool = ..., historySyncConfig: _Optional[_Union[DeviceProps.HistorySyncConfig, _Mapping]] = ...) -> None: ...

class CompanionEphemeralIdentity(_message.Message):
    __slots__ = ("publicKey", "deviceType", "ref")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    DEVICETYPE_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    deviceType: DeviceProps.PlatformType
    ref: str
    def __init__(self, publicKey: _Optional[bytes] = ..., deviceType: _Optional[_Union[DeviceProps.PlatformType, str]] = ..., ref: _Optional[str] = ...) -> None: ...

class CompanionCommitment(_message.Message):
    __slots__ = ("hash",)
    HASH_FIELD_NUMBER: _ClassVar[int]
    hash: bytes
    def __init__(self, hash: _Optional[bytes] = ...) -> None: ...

class ProloguePayload(_message.Message):
    __slots__ = ("companionEphemeralIdentity", "commitment")
    COMPANIONEPHEMERALIDENTITY_FIELD_NUMBER: _ClassVar[int]
    COMMITMENT_FIELD_NUMBER: _ClassVar[int]
    companionEphemeralIdentity: bytes
    commitment: CompanionCommitment
    def __init__(self, companionEphemeralIdentity: _Optional[bytes] = ..., commitment: _Optional[_Union[CompanionCommitment, _Mapping]] = ...) -> None: ...

class PrimaryEphemeralIdentity(_message.Message):
    __slots__ = ("publicKey", "nonce")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    nonce: bytes
    def __init__(self, publicKey: _Optional[bytes] = ..., nonce: _Optional[bytes] = ...) -> None: ...

class PairingRequest(_message.Message):
    __slots__ = ("companionPublicKey", "companionIdentityKey", "advSecret")
    COMPANIONPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    COMPANIONIDENTITYKEY_FIELD_NUMBER: _ClassVar[int]
    ADVSECRET_FIELD_NUMBER: _ClassVar[int]
    companionPublicKey: bytes
    companionIdentityKey: bytes
    advSecret: bytes
    def __init__(self, companionPublicKey: _Optional[bytes] = ..., companionIdentityKey: _Optional[bytes] = ..., advSecret: _Optional[bytes] = ...) -> None: ...

class EncryptedPairingRequest(_message.Message):
    __slots__ = ("encryptedPayload", "IV")
    ENCRYPTEDPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    encryptedPayload: bytes
    IV: bytes
    def __init__(self, encryptedPayload: _Optional[bytes] = ..., IV: _Optional[bytes] = ...) -> None: ...

class ClientPairingProps(_message.Message):
    __slots__ = ("isChatDbLidMigrated", "isSyncdPureLidSession")
    ISCHATDBLIDMIGRATED_FIELD_NUMBER: _ClassVar[int]
    ISSYNCDPURELIDSESSION_FIELD_NUMBER: _ClassVar[int]
    isChatDbLidMigrated: bool
    isSyncdPureLidSession: bool
    def __init__(self, isChatDbLidMigrated: bool = ..., isSyncdPureLidSession: bool = ...) -> None: ...
