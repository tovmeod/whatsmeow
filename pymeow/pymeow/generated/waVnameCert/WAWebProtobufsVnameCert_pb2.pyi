from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class BizAccountLinkInfo(_message.Message):
    __slots__ = ("whatsappBizAcctFbid", "whatsappAcctNumber", "issueTime", "hostStorage", "accountType")
    class AccountType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ENTERPRISE: _ClassVar[BizAccountLinkInfo.AccountType]
    ENTERPRISE: BizAccountLinkInfo.AccountType
    class HostStorageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ON_PREMISE: _ClassVar[BizAccountLinkInfo.HostStorageType]
        FACEBOOK: _ClassVar[BizAccountLinkInfo.HostStorageType]
    ON_PREMISE: BizAccountLinkInfo.HostStorageType
    FACEBOOK: BizAccountLinkInfo.HostStorageType
    WHATSAPPBIZACCTFBID_FIELD_NUMBER: _ClassVar[int]
    WHATSAPPACCTNUMBER_FIELD_NUMBER: _ClassVar[int]
    ISSUETIME_FIELD_NUMBER: _ClassVar[int]
    HOSTSTORAGE_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    whatsappBizAcctFbid: int
    whatsappAcctNumber: str
    issueTime: int
    hostStorage: BizAccountLinkInfo.HostStorageType
    accountType: BizAccountLinkInfo.AccountType
    def __init__(self, whatsappBizAcctFbid: _Optional[int] = ..., whatsappAcctNumber: _Optional[str] = ..., issueTime: _Optional[int] = ..., hostStorage: _Optional[_Union[BizAccountLinkInfo.HostStorageType, str]] = ..., accountType: _Optional[_Union[BizAccountLinkInfo.AccountType, str]] = ...) -> None: ...

class BizIdentityInfo(_message.Message):
    __slots__ = ("vlevel", "vnameCert", "signed", "revoked", "hostStorage", "actualActors", "privacyModeTS", "featureControls")
    class ActualActorsType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SELF: _ClassVar[BizIdentityInfo.ActualActorsType]
        BSP: _ClassVar[BizIdentityInfo.ActualActorsType]
    SELF: BizIdentityInfo.ActualActorsType
    BSP: BizIdentityInfo.ActualActorsType
    class HostStorageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ON_PREMISE: _ClassVar[BizIdentityInfo.HostStorageType]
        FACEBOOK: _ClassVar[BizIdentityInfo.HostStorageType]
    ON_PREMISE: BizIdentityInfo.HostStorageType
    FACEBOOK: BizIdentityInfo.HostStorageType
    class VerifiedLevelValue(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[BizIdentityInfo.VerifiedLevelValue]
        LOW: _ClassVar[BizIdentityInfo.VerifiedLevelValue]
        HIGH: _ClassVar[BizIdentityInfo.VerifiedLevelValue]
    UNKNOWN: BizIdentityInfo.VerifiedLevelValue
    LOW: BizIdentityInfo.VerifiedLevelValue
    HIGH: BizIdentityInfo.VerifiedLevelValue
    VLEVEL_FIELD_NUMBER: _ClassVar[int]
    VNAMECERT_FIELD_NUMBER: _ClassVar[int]
    SIGNED_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    HOSTSTORAGE_FIELD_NUMBER: _ClassVar[int]
    ACTUALACTORS_FIELD_NUMBER: _ClassVar[int]
    PRIVACYMODETS_FIELD_NUMBER: _ClassVar[int]
    FEATURECONTROLS_FIELD_NUMBER: _ClassVar[int]
    vlevel: BizIdentityInfo.VerifiedLevelValue
    vnameCert: VerifiedNameCertificate
    signed: bool
    revoked: bool
    hostStorage: BizIdentityInfo.HostStorageType
    actualActors: BizIdentityInfo.ActualActorsType
    privacyModeTS: int
    featureControls: int
    def __init__(self, vlevel: _Optional[_Union[BizIdentityInfo.VerifiedLevelValue, str]] = ..., vnameCert: _Optional[_Union[VerifiedNameCertificate, _Mapping]] = ..., signed: bool = ..., revoked: bool = ..., hostStorage: _Optional[_Union[BizIdentityInfo.HostStorageType, str]] = ..., actualActors: _Optional[_Union[BizIdentityInfo.ActualActorsType, str]] = ..., privacyModeTS: _Optional[int] = ..., featureControls: _Optional[int] = ...) -> None: ...

class LocalizedName(_message.Message):
    __slots__ = ("lg", "lc", "verifiedName")
    LG_FIELD_NUMBER: _ClassVar[int]
    LC_FIELD_NUMBER: _ClassVar[int]
    VERIFIEDNAME_FIELD_NUMBER: _ClassVar[int]
    lg: str
    lc: str
    verifiedName: str
    def __init__(self, lg: _Optional[str] = ..., lc: _Optional[str] = ..., verifiedName: _Optional[str] = ...) -> None: ...

class VerifiedNameCertificate(_message.Message):
    __slots__ = ("details", "signature", "serverSignature")
    class Details(_message.Message):
        __slots__ = ("serial", "issuer", "verifiedName", "localizedNames", "issueTime")
        SERIAL_FIELD_NUMBER: _ClassVar[int]
        ISSUER_FIELD_NUMBER: _ClassVar[int]
        VERIFIEDNAME_FIELD_NUMBER: _ClassVar[int]
        LOCALIZEDNAMES_FIELD_NUMBER: _ClassVar[int]
        ISSUETIME_FIELD_NUMBER: _ClassVar[int]
        serial: int
        issuer: str
        verifiedName: str
        localizedNames: _containers.RepeatedCompositeFieldContainer[LocalizedName]
        issueTime: int
        def __init__(self, serial: _Optional[int] = ..., issuer: _Optional[str] = ..., verifiedName: _Optional[str] = ..., localizedNames: _Optional[_Iterable[_Union[LocalizedName, _Mapping]]] = ..., issueTime: _Optional[int] = ...) -> None: ...
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SERVERSIGNATURE_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    signature: bytes
    serverSignature: bytes
    def __init__(self, details: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., serverSignature: _Optional[bytes] = ...) -> None: ...

class BizAccountPayload(_message.Message):
    __slots__ = ("vnameCert", "bizAcctLinkInfo")
    VNAMECERT_FIELD_NUMBER: _ClassVar[int]
    BIZACCTLINKINFO_FIELD_NUMBER: _ClassVar[int]
    vnameCert: VerifiedNameCertificate
    bizAcctLinkInfo: bytes
    def __init__(self, vnameCert: _Optional[_Union[VerifiedNameCertificate, _Mapping]] = ..., bizAcctLinkInfo: _Optional[bytes] = ...) -> None: ...
