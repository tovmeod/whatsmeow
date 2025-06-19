from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ADVEncryptionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    E2EE: _ClassVar[ADVEncryptionType]
    HOSTED: _ClassVar[ADVEncryptionType]
E2EE: ADVEncryptionType
HOSTED: ADVEncryptionType

class ADVKeyIndexList(_message.Message):
    __slots__ = ("rawID", "timestamp", "currentIndex", "validIndexes", "accountType")
    RAWID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CURRENTINDEX_FIELD_NUMBER: _ClassVar[int]
    VALIDINDEXES_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    rawID: int
    timestamp: int
    currentIndex: int
    validIndexes: _containers.RepeatedScalarFieldContainer[int]
    accountType: ADVEncryptionType
    def __init__(self, rawID: _Optional[int] = ..., timestamp: _Optional[int] = ..., currentIndex: _Optional[int] = ..., validIndexes: _Optional[_Iterable[int]] = ..., accountType: _Optional[_Union[ADVEncryptionType, str]] = ...) -> None: ...

class ADVSignedKeyIndexList(_message.Message):
    __slots__ = ("details", "accountSignature", "accountSignatureKey")
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSIGNATURE_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSIGNATUREKEY_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    accountSignature: bytes
    accountSignatureKey: bytes
    def __init__(self, details: _Optional[bytes] = ..., accountSignature: _Optional[bytes] = ..., accountSignatureKey: _Optional[bytes] = ...) -> None: ...

class ADVDeviceIdentity(_message.Message):
    __slots__ = ("rawID", "timestamp", "keyIndex", "accountType", "deviceType")
    RAWID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    KEYINDEX_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    DEVICETYPE_FIELD_NUMBER: _ClassVar[int]
    rawID: int
    timestamp: int
    keyIndex: int
    accountType: ADVEncryptionType
    deviceType: ADVEncryptionType
    def __init__(self, rawID: _Optional[int] = ..., timestamp: _Optional[int] = ..., keyIndex: _Optional[int] = ..., accountType: _Optional[_Union[ADVEncryptionType, str]] = ..., deviceType: _Optional[_Union[ADVEncryptionType, str]] = ...) -> None: ...

class ADVSignedDeviceIdentity(_message.Message):
    __slots__ = ("details", "accountSignatureKey", "accountSignature", "deviceSignature")
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSIGNATUREKEY_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSIGNATURE_FIELD_NUMBER: _ClassVar[int]
    DEVICESIGNATURE_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    accountSignatureKey: bytes
    accountSignature: bytes
    deviceSignature: bytes
    def __init__(self, details: _Optional[bytes] = ..., accountSignatureKey: _Optional[bytes] = ..., accountSignature: _Optional[bytes] = ..., deviceSignature: _Optional[bytes] = ...) -> None: ...

class ADVSignedDeviceIdentityHMAC(_message.Message):
    __slots__ = ("details", "HMAC", "accountType")
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    HMAC_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTTYPE_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    HMAC: bytes
    accountType: ADVEncryptionType
    def __init__(self, details: _Optional[bytes] = ..., HMAC: _Optional[bytes] = ..., accountType: _Optional[_Union[ADVEncryptionType, str]] = ...) -> None: ...
