from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ClientPayload(_message.Message):
    __slots__ = ("username", "passive", "userAgent", "webInfo", "pushName", "sessionID", "shortConnect", "connectType", "connectReason", "shards", "dnsSource", "connectAttemptCount", "device", "devicePairingData", "product", "fbCat", "fbUserAgent", "oc", "lc", "iosAppExtension", "fbAppID", "fbDeviceID", "pull", "paddingBytes", "yearClass", "memClass", "interopData", "trafficAnonymization", "lidDbMigrated", "accountType")
    class TrafficAnonymization(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        OFF: _ClassVar[ClientPayload.TrafficAnonymization]
        STANDARD: _ClassVar[ClientPayload.TrafficAnonymization]
    OFF: ClientPayload.TrafficAnonymization
    STANDARD: ClientPayload.TrafficAnonymization
    class AccountType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[ClientPayload.AccountType]
        GUEST: _ClassVar[ClientPayload.AccountType]
    DEFAULT: ClientPayload.AccountType
    GUEST: ClientPayload.AccountType
    class Product(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        WHATSAPP: _ClassVar[ClientPayload.Product]
        MESSENGER: _ClassVar[ClientPayload.Product]
        INTEROP: _ClassVar[ClientPayload.Product]
        INTEROP_MSGR: _ClassVar[ClientPayload.Product]
        WHATSAPP_LID: _ClassVar[ClientPayload.Product]
    WHATSAPP: ClientPayload.Product
    MESSENGER: ClientPayload.Product
    INTEROP: ClientPayload.Product
    INTEROP_MSGR: ClientPayload.Product
    WHATSAPP_LID: ClientPayload.Product
    class ConnectType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CELLULAR_UNKNOWN: _ClassVar[ClientPayload.ConnectType]
        WIFI_UNKNOWN: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_EDGE: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_IDEN: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_UMTS: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_EVDO: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_GPRS: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_HSDPA: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_HSUPA: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_HSPA: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_CDMA: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_1XRTT: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_EHRPD: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_LTE: _ClassVar[ClientPayload.ConnectType]
        CELLULAR_HSPAP: _ClassVar[ClientPayload.ConnectType]
    CELLULAR_UNKNOWN: ClientPayload.ConnectType
    WIFI_UNKNOWN: ClientPayload.ConnectType
    CELLULAR_EDGE: ClientPayload.ConnectType
    CELLULAR_IDEN: ClientPayload.ConnectType
    CELLULAR_UMTS: ClientPayload.ConnectType
    CELLULAR_EVDO: ClientPayload.ConnectType
    CELLULAR_GPRS: ClientPayload.ConnectType
    CELLULAR_HSDPA: ClientPayload.ConnectType
    CELLULAR_HSUPA: ClientPayload.ConnectType
    CELLULAR_HSPA: ClientPayload.ConnectType
    CELLULAR_CDMA: ClientPayload.ConnectType
    CELLULAR_1XRTT: ClientPayload.ConnectType
    CELLULAR_EHRPD: ClientPayload.ConnectType
    CELLULAR_LTE: ClientPayload.ConnectType
    CELLULAR_HSPAP: ClientPayload.ConnectType
    class ConnectReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        PUSH: _ClassVar[ClientPayload.ConnectReason]
        USER_ACTIVATED: _ClassVar[ClientPayload.ConnectReason]
        SCHEDULED: _ClassVar[ClientPayload.ConnectReason]
        ERROR_RECONNECT: _ClassVar[ClientPayload.ConnectReason]
        NETWORK_SWITCH: _ClassVar[ClientPayload.ConnectReason]
        PING_RECONNECT: _ClassVar[ClientPayload.ConnectReason]
        UNKNOWN: _ClassVar[ClientPayload.ConnectReason]
    PUSH: ClientPayload.ConnectReason
    USER_ACTIVATED: ClientPayload.ConnectReason
    SCHEDULED: ClientPayload.ConnectReason
    ERROR_RECONNECT: ClientPayload.ConnectReason
    NETWORK_SWITCH: ClientPayload.ConnectReason
    PING_RECONNECT: ClientPayload.ConnectReason
    UNKNOWN: ClientPayload.ConnectReason
    class IOSAppExtension(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SHARE_EXTENSION: _ClassVar[ClientPayload.IOSAppExtension]
        SERVICE_EXTENSION: _ClassVar[ClientPayload.IOSAppExtension]
        INTENTS_EXTENSION: _ClassVar[ClientPayload.IOSAppExtension]
    SHARE_EXTENSION: ClientPayload.IOSAppExtension
    SERVICE_EXTENSION: ClientPayload.IOSAppExtension
    INTENTS_EXTENSION: ClientPayload.IOSAppExtension
    class DNSSource(_message.Message):
        __slots__ = ("dnsMethod", "appCached")
        class DNSResolutionMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SYSTEM: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
            GOOGLE: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
            HARDCODED: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
            OVERRIDE: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
            FALLBACK: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
            MNS: _ClassVar[ClientPayload.DNSSource.DNSResolutionMethod]
        SYSTEM: ClientPayload.DNSSource.DNSResolutionMethod
        GOOGLE: ClientPayload.DNSSource.DNSResolutionMethod
        HARDCODED: ClientPayload.DNSSource.DNSResolutionMethod
        OVERRIDE: ClientPayload.DNSSource.DNSResolutionMethod
        FALLBACK: ClientPayload.DNSSource.DNSResolutionMethod
        MNS: ClientPayload.DNSSource.DNSResolutionMethod
        DNSMETHOD_FIELD_NUMBER: _ClassVar[int]
        APPCACHED_FIELD_NUMBER: _ClassVar[int]
        dnsMethod: ClientPayload.DNSSource.DNSResolutionMethod
        appCached: bool
        def __init__(self, dnsMethod: _Optional[_Union[ClientPayload.DNSSource.DNSResolutionMethod, str]] = ..., appCached: bool = ...) -> None: ...
    class WebInfo(_message.Message):
        __slots__ = ("refToken", "version", "webdPayload", "webSubPlatform")
        class WebSubPlatform(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            WEB_BROWSER: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
            APP_STORE: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
            WIN_STORE: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
            DARWIN: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
            WIN32: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
            WIN_HYBRID: _ClassVar[ClientPayload.WebInfo.WebSubPlatform]
        WEB_BROWSER: ClientPayload.WebInfo.WebSubPlatform
        APP_STORE: ClientPayload.WebInfo.WebSubPlatform
        WIN_STORE: ClientPayload.WebInfo.WebSubPlatform
        DARWIN: ClientPayload.WebInfo.WebSubPlatform
        WIN32: ClientPayload.WebInfo.WebSubPlatform
        WIN_HYBRID: ClientPayload.WebInfo.WebSubPlatform
        class WebdPayload(_message.Message):
            __slots__ = ("usesParticipantInKey", "supportsStarredMessages", "supportsDocumentMessages", "supportsURLMessages", "supportsMediaRetry", "supportsE2EImage", "supportsE2EVideo", "supportsE2EAudio", "supportsE2EDocument", "documentTypes", "features")
            USESPARTICIPANTINKEY_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSSTARREDMESSAGES_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSDOCUMENTMESSAGES_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSURLMESSAGES_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSMEDIARETRY_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSE2EIMAGE_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSE2EVIDEO_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSE2EAUDIO_FIELD_NUMBER: _ClassVar[int]
            SUPPORTSE2EDOCUMENT_FIELD_NUMBER: _ClassVar[int]
            DOCUMENTTYPES_FIELD_NUMBER: _ClassVar[int]
            FEATURES_FIELD_NUMBER: _ClassVar[int]
            usesParticipantInKey: bool
            supportsStarredMessages: bool
            supportsDocumentMessages: bool
            supportsURLMessages: bool
            supportsMediaRetry: bool
            supportsE2EImage: bool
            supportsE2EVideo: bool
            supportsE2EAudio: bool
            supportsE2EDocument: bool
            documentTypes: str
            features: bytes
            def __init__(self, usesParticipantInKey: bool = ..., supportsStarredMessages: bool = ..., supportsDocumentMessages: bool = ..., supportsURLMessages: bool = ..., supportsMediaRetry: bool = ..., supportsE2EImage: bool = ..., supportsE2EVideo: bool = ..., supportsE2EAudio: bool = ..., supportsE2EDocument: bool = ..., documentTypes: _Optional[str] = ..., features: _Optional[bytes] = ...) -> None: ...
        REFTOKEN_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        WEBDPAYLOAD_FIELD_NUMBER: _ClassVar[int]
        WEBSUBPLATFORM_FIELD_NUMBER: _ClassVar[int]
        refToken: str
        version: str
        webdPayload: ClientPayload.WebInfo.WebdPayload
        webSubPlatform: ClientPayload.WebInfo.WebSubPlatform
        def __init__(self, refToken: _Optional[str] = ..., version: _Optional[str] = ..., webdPayload: _Optional[_Union[ClientPayload.WebInfo.WebdPayload, _Mapping]] = ..., webSubPlatform: _Optional[_Union[ClientPayload.WebInfo.WebSubPlatform, str]] = ...) -> None: ...
    class UserAgent(_message.Message):
        __slots__ = ("platform", "appVersion", "mcc", "mnc", "osVersion", "manufacturer", "device", "osBuildNumber", "phoneID", "releaseChannel", "localeLanguageIso6391", "localeCountryIso31661Alpha2", "deviceBoard", "deviceExpID", "deviceType", "deviceModelType")
        class DeviceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            PHONE: _ClassVar[ClientPayload.UserAgent.DeviceType]
            TABLET: _ClassVar[ClientPayload.UserAgent.DeviceType]
            DESKTOP: _ClassVar[ClientPayload.UserAgent.DeviceType]
            WEARABLE: _ClassVar[ClientPayload.UserAgent.DeviceType]
            VR: _ClassVar[ClientPayload.UserAgent.DeviceType]
        PHONE: ClientPayload.UserAgent.DeviceType
        TABLET: ClientPayload.UserAgent.DeviceType
        DESKTOP: ClientPayload.UserAgent.DeviceType
        WEARABLE: ClientPayload.UserAgent.DeviceType
        VR: ClientPayload.UserAgent.DeviceType
        class ReleaseChannel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            RELEASE: _ClassVar[ClientPayload.UserAgent.ReleaseChannel]
            BETA: _ClassVar[ClientPayload.UserAgent.ReleaseChannel]
            ALPHA: _ClassVar[ClientPayload.UserAgent.ReleaseChannel]
            DEBUG: _ClassVar[ClientPayload.UserAgent.ReleaseChannel]
        RELEASE: ClientPayload.UserAgent.ReleaseChannel
        BETA: ClientPayload.UserAgent.ReleaseChannel
        ALPHA: ClientPayload.UserAgent.ReleaseChannel
        DEBUG: ClientPayload.UserAgent.ReleaseChannel
        class Platform(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            IOS: _ClassVar[ClientPayload.UserAgent.Platform]
            WINDOWS_PHONE: _ClassVar[ClientPayload.UserAgent.Platform]
            BLACKBERRY: _ClassVar[ClientPayload.UserAgent.Platform]
            BLACKBERRYX: _ClassVar[ClientPayload.UserAgent.Platform]
            S40: _ClassVar[ClientPayload.UserAgent.Platform]
            S60: _ClassVar[ClientPayload.UserAgent.Platform]
            PYTHON_CLIENT: _ClassVar[ClientPayload.UserAgent.Platform]
            TIZEN: _ClassVar[ClientPayload.UserAgent.Platform]
            ENTERPRISE: _ClassVar[ClientPayload.UserAgent.Platform]
            SMB_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            KAIOS: _ClassVar[ClientPayload.UserAgent.Platform]
            SMB_IOS: _ClassVar[ClientPayload.UserAgent.Platform]
            WINDOWS: _ClassVar[ClientPayload.UserAgent.Platform]
            WEB: _ClassVar[ClientPayload.UserAgent.Platform]
            PORTAL: _ClassVar[ClientPayload.UserAgent.Platform]
            GREEN_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            GREEN_IPHONE: _ClassVar[ClientPayload.UserAgent.Platform]
            BLUE_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            BLUE_IPHONE: _ClassVar[ClientPayload.UserAgent.Platform]
            FBLITE_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            MLITE_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            IGLITE_ANDROID: _ClassVar[ClientPayload.UserAgent.Platform]
            PAGE: _ClassVar[ClientPayload.UserAgent.Platform]
            MACOS: _ClassVar[ClientPayload.UserAgent.Platform]
            OCULUS_MSG: _ClassVar[ClientPayload.UserAgent.Platform]
            OCULUS_CALL: _ClassVar[ClientPayload.UserAgent.Platform]
            MILAN: _ClassVar[ClientPayload.UserAgent.Platform]
            CAPI: _ClassVar[ClientPayload.UserAgent.Platform]
            WEAROS: _ClassVar[ClientPayload.UserAgent.Platform]
            ARDEVICE: _ClassVar[ClientPayload.UserAgent.Platform]
            VRDEVICE: _ClassVar[ClientPayload.UserAgent.Platform]
            BLUE_WEB: _ClassVar[ClientPayload.UserAgent.Platform]
            IPAD: _ClassVar[ClientPayload.UserAgent.Platform]
            TEST: _ClassVar[ClientPayload.UserAgent.Platform]
            SMART_GLASSES: _ClassVar[ClientPayload.UserAgent.Platform]
        ANDROID: ClientPayload.UserAgent.Platform
        IOS: ClientPayload.UserAgent.Platform
        WINDOWS_PHONE: ClientPayload.UserAgent.Platform
        BLACKBERRY: ClientPayload.UserAgent.Platform
        BLACKBERRYX: ClientPayload.UserAgent.Platform
        S40: ClientPayload.UserAgent.Platform
        S60: ClientPayload.UserAgent.Platform
        PYTHON_CLIENT: ClientPayload.UserAgent.Platform
        TIZEN: ClientPayload.UserAgent.Platform
        ENTERPRISE: ClientPayload.UserAgent.Platform
        SMB_ANDROID: ClientPayload.UserAgent.Platform
        KAIOS: ClientPayload.UserAgent.Platform
        SMB_IOS: ClientPayload.UserAgent.Platform
        WINDOWS: ClientPayload.UserAgent.Platform
        WEB: ClientPayload.UserAgent.Platform
        PORTAL: ClientPayload.UserAgent.Platform
        GREEN_ANDROID: ClientPayload.UserAgent.Platform
        GREEN_IPHONE: ClientPayload.UserAgent.Platform
        BLUE_ANDROID: ClientPayload.UserAgent.Platform
        BLUE_IPHONE: ClientPayload.UserAgent.Platform
        FBLITE_ANDROID: ClientPayload.UserAgent.Platform
        MLITE_ANDROID: ClientPayload.UserAgent.Platform
        IGLITE_ANDROID: ClientPayload.UserAgent.Platform
        PAGE: ClientPayload.UserAgent.Platform
        MACOS: ClientPayload.UserAgent.Platform
        OCULUS_MSG: ClientPayload.UserAgent.Platform
        OCULUS_CALL: ClientPayload.UserAgent.Platform
        MILAN: ClientPayload.UserAgent.Platform
        CAPI: ClientPayload.UserAgent.Platform
        WEAROS: ClientPayload.UserAgent.Platform
        ARDEVICE: ClientPayload.UserAgent.Platform
        VRDEVICE: ClientPayload.UserAgent.Platform
        BLUE_WEB: ClientPayload.UserAgent.Platform
        IPAD: ClientPayload.UserAgent.Platform
        TEST: ClientPayload.UserAgent.Platform
        SMART_GLASSES: ClientPayload.UserAgent.Platform
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
        PLATFORM_FIELD_NUMBER: _ClassVar[int]
        APPVERSION_FIELD_NUMBER: _ClassVar[int]
        MCC_FIELD_NUMBER: _ClassVar[int]
        MNC_FIELD_NUMBER: _ClassVar[int]
        OSVERSION_FIELD_NUMBER: _ClassVar[int]
        MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
        DEVICE_FIELD_NUMBER: _ClassVar[int]
        OSBUILDNUMBER_FIELD_NUMBER: _ClassVar[int]
        PHONEID_FIELD_NUMBER: _ClassVar[int]
        RELEASECHANNEL_FIELD_NUMBER: _ClassVar[int]
        LOCALELANGUAGEISO6391_FIELD_NUMBER: _ClassVar[int]
        LOCALECOUNTRYISO31661ALPHA2_FIELD_NUMBER: _ClassVar[int]
        DEVICEBOARD_FIELD_NUMBER: _ClassVar[int]
        DEVICEEXPID_FIELD_NUMBER: _ClassVar[int]
        DEVICETYPE_FIELD_NUMBER: _ClassVar[int]
        DEVICEMODELTYPE_FIELD_NUMBER: _ClassVar[int]
        platform: ClientPayload.UserAgent.Platform
        appVersion: ClientPayload.UserAgent.AppVersion
        mcc: str
        mnc: str
        osVersion: str
        manufacturer: str
        device: str
        osBuildNumber: str
        phoneID: str
        releaseChannel: ClientPayload.UserAgent.ReleaseChannel
        localeLanguageIso6391: str
        localeCountryIso31661Alpha2: str
        deviceBoard: str
        deviceExpID: str
        deviceType: ClientPayload.UserAgent.DeviceType
        deviceModelType: str
        def __init__(self, platform: _Optional[_Union[ClientPayload.UserAgent.Platform, str]] = ..., appVersion: _Optional[_Union[ClientPayload.UserAgent.AppVersion, _Mapping]] = ..., mcc: _Optional[str] = ..., mnc: _Optional[str] = ..., osVersion: _Optional[str] = ..., manufacturer: _Optional[str] = ..., device: _Optional[str] = ..., osBuildNumber: _Optional[str] = ..., phoneID: _Optional[str] = ..., releaseChannel: _Optional[_Union[ClientPayload.UserAgent.ReleaseChannel, str]] = ..., localeLanguageIso6391: _Optional[str] = ..., localeCountryIso31661Alpha2: _Optional[str] = ..., deviceBoard: _Optional[str] = ..., deviceExpID: _Optional[str] = ..., deviceType: _Optional[_Union[ClientPayload.UserAgent.DeviceType, str]] = ..., deviceModelType: _Optional[str] = ...) -> None: ...
    class InteropData(_message.Message):
        __slots__ = ("accountID", "token", "enableReadReceipts")
        ACCOUNTID_FIELD_NUMBER: _ClassVar[int]
        TOKEN_FIELD_NUMBER: _ClassVar[int]
        ENABLEREADRECEIPTS_FIELD_NUMBER: _ClassVar[int]
        accountID: int
        token: bytes
        enableReadReceipts: bool
        def __init__(self, accountID: _Optional[int] = ..., token: _Optional[bytes] = ..., enableReadReceipts: bool = ...) -> None: ...
    class DevicePairingRegistrationData(_message.Message):
        __slots__ = ("eRegid", "eKeytype", "eIdent", "eSkeyID", "eSkeyVal", "eSkeySig", "buildHash", "deviceProps")
        EREGID_FIELD_NUMBER: _ClassVar[int]
        EKEYTYPE_FIELD_NUMBER: _ClassVar[int]
        EIDENT_FIELD_NUMBER: _ClassVar[int]
        ESKEYID_FIELD_NUMBER: _ClassVar[int]
        ESKEYVAL_FIELD_NUMBER: _ClassVar[int]
        ESKEYSIG_FIELD_NUMBER: _ClassVar[int]
        BUILDHASH_FIELD_NUMBER: _ClassVar[int]
        DEVICEPROPS_FIELD_NUMBER: _ClassVar[int]
        eRegid: bytes
        eKeytype: bytes
        eIdent: bytes
        eSkeyID: bytes
        eSkeyVal: bytes
        eSkeySig: bytes
        buildHash: bytes
        deviceProps: bytes
        def __init__(self, eRegid: _Optional[bytes] = ..., eKeytype: _Optional[bytes] = ..., eIdent: _Optional[bytes] = ..., eSkeyID: _Optional[bytes] = ..., eSkeyVal: _Optional[bytes] = ..., eSkeySig: _Optional[bytes] = ..., buildHash: _Optional[bytes] = ..., deviceProps: _Optional[bytes] = ...) -> None: ...
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSIVE_FIELD_NUMBER: _ClassVar[int]
    USERAGENT_FIELD_NUMBER: _ClassVar[int]
    WEBINFO_FIELD_NUMBER: _ClassVar[int]
    PUSHNAME_FIELD_NUMBER: _ClassVar[int]
    SESSIONID_FIELD_NUMBER: _ClassVar[int]
    SHORTCONNECT_FIELD_NUMBER: _ClassVar[int]
    CONNECTTYPE_FIELD_NUMBER: _ClassVar[int]
    CONNECTREASON_FIELD_NUMBER: _ClassVar[int]
    SHARDS_FIELD_NUMBER: _ClassVar[int]
    DNSSOURCE_FIELD_NUMBER: _ClassVar[int]
    CONNECTATTEMPTCOUNT_FIELD_NUMBER: _ClassVar[int]
    DEVICE_FIELD_NUMBER: _ClassVar[int]
    DEVICEPAIRINGDATA_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_FIELD_NUMBER: _ClassVar[int]
    FBCAT_FIELD_NUMBER: _ClassVar[int]
    FBUSERAGENT_FIELD_NUMBER: _ClassVar[int]
    OC_FIELD_NUMBER: _ClassVar[int]
    LC_FIELD_NUMBER: _ClassVar[int]
    IOSAPPEXTENSION_FIELD_NUMBER: _ClassVar[int]
    FBAPPID_FIELD_NUMBER: _ClassVar[int]
    FBDEVICEID_FIELD_NUMBER: _ClassVar[int]
    PULL_FIELD_NUMBER: _ClassVar[int]
    PADDINGBYTES_FIELD_NUMBER: _ClassVar[int]
    YEARCLASS_FIELD_NUMBER: _ClassVar[int]
    MEMCLASS_FIELD_NUMBER: _ClassVar[int]
    INTEROPDATA_FIELD_NUMBER: _ClassVar[int]
    TRAFFICANONYMIZATION_FIELD_NUMBER: _ClassVar[int]
    LIDDBMIGRATED_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    username: int
    passive: bool
    userAgent: ClientPayload.UserAgent
    webInfo: ClientPayload.WebInfo
    pushName: str
    sessionID: int
    shortConnect: bool
    connectType: ClientPayload.ConnectType
    connectReason: ClientPayload.ConnectReason
    shards: _containers.RepeatedScalarFieldContainer[int]
    dnsSource: ClientPayload.DNSSource
    connectAttemptCount: int
    device: int
    devicePairingData: ClientPayload.DevicePairingRegistrationData
    product: ClientPayload.Product
    fbCat: bytes
    fbUserAgent: bytes
    oc: bool
    lc: int
    iosAppExtension: ClientPayload.IOSAppExtension
    fbAppID: int
    fbDeviceID: bytes
    pull: bool
    paddingBytes: bytes
    yearClass: int
    memClass: int
    interopData: ClientPayload.InteropData
    trafficAnonymization: ClientPayload.TrafficAnonymization
    lidDbMigrated: bool
    accountType: ClientPayload.AccountType
    def __init__(self, username: _Optional[int] = ..., passive: bool = ..., userAgent: _Optional[_Union[ClientPayload.UserAgent, _Mapping]] = ..., webInfo: _Optional[_Union[ClientPayload.WebInfo, _Mapping]] = ..., pushName: _Optional[str] = ..., sessionID: _Optional[int] = ..., shortConnect: bool = ..., connectType: _Optional[_Union[ClientPayload.ConnectType, str]] = ..., connectReason: _Optional[_Union[ClientPayload.ConnectReason, str]] = ..., shards: _Optional[_Iterable[int]] = ..., dnsSource: _Optional[_Union[ClientPayload.DNSSource, _Mapping]] = ..., connectAttemptCount: _Optional[int] = ..., device: _Optional[int] = ..., devicePairingData: _Optional[_Union[ClientPayload.DevicePairingRegistrationData, _Mapping]] = ..., product: _Optional[_Union[ClientPayload.Product, str]] = ..., fbCat: _Optional[bytes] = ..., fbUserAgent: _Optional[bytes] = ..., oc: bool = ..., lc: _Optional[int] = ..., iosAppExtension: _Optional[_Union[ClientPayload.IOSAppExtension, str]] = ..., fbAppID: _Optional[int] = ..., fbDeviceID: _Optional[bytes] = ..., pull: bool = ..., paddingBytes: _Optional[bytes] = ..., yearClass: _Optional[int] = ..., memClass: _Optional[int] = ..., interopData: _Optional[_Union[ClientPayload.InteropData, _Mapping]] = ..., trafficAnonymization: _Optional[_Union[ClientPayload.TrafficAnonymization, str]] = ..., lidDbMigrated: bool = ..., accountType: _Optional[_Union[ClientPayload.AccountType, str]] = ...) -> None: ...

class HandshakeMessage(_message.Message):
    __slots__ = ("clientHello", "serverHello", "clientFinish")
    class ClientFinish(_message.Message):
        __slots__ = ("static", "payload")
        STATIC_FIELD_NUMBER: _ClassVar[int]
        PAYLOAD_FIELD_NUMBER: _ClassVar[int]
        static: bytes
        payload: bytes
        def __init__(self, static: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...
    class ServerHello(_message.Message):
        __slots__ = ("ephemeral", "static", "payload")
        EPHEMERAL_FIELD_NUMBER: _ClassVar[int]
        STATIC_FIELD_NUMBER: _ClassVar[int]
        PAYLOAD_FIELD_NUMBER: _ClassVar[int]
        ephemeral: bytes
        static: bytes
        payload: bytes
        def __init__(self, ephemeral: _Optional[bytes] = ..., static: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...
    class ClientHello(_message.Message):
        __slots__ = ("ephemeral", "static", "payload")
        EPHEMERAL_FIELD_NUMBER: _ClassVar[int]
        STATIC_FIELD_NUMBER: _ClassVar[int]
        PAYLOAD_FIELD_NUMBER: _ClassVar[int]
        ephemeral: bytes
        static: bytes
        payload: bytes
        def __init__(self, ephemeral: _Optional[bytes] = ..., static: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...
    CLIENTHELLO_FIELD_NUMBER: _ClassVar[int]
    SERVERHELLO_FIELD_NUMBER: _ClassVar[int]
    CLIENTFINISH_FIELD_NUMBER: _ClassVar[int]
    clientHello: HandshakeMessage.ClientHello
    serverHello: HandshakeMessage.ServerHello
    clientFinish: HandshakeMessage.ClientFinish
    def __init__(self, clientHello: _Optional[_Union[HandshakeMessage.ClientHello, _Mapping]] = ..., serverHello: _Optional[_Union[HandshakeMessage.ServerHello, _Mapping]] = ..., clientFinish: _Optional[_Union[HandshakeMessage.ClientFinish, _Mapping]] = ...) -> None: ...
