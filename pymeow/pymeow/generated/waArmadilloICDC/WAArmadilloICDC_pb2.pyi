from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ICDCIdentityList(_message.Message):
    __slots__ = ("seq", "timestamp", "devices", "signingDeviceIndex")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    SIGNINGDEVICEINDEX_FIELD_NUMBER: _ClassVar[int]
    seq: int
    timestamp: int
    devices: _containers.RepeatedScalarFieldContainer[bytes]
    signingDeviceIndex: int
    def __init__(self, seq: _Optional[int] = ..., timestamp: _Optional[int] = ..., devices: _Optional[_Iterable[bytes]] = ..., signingDeviceIndex: _Optional[int] = ...) -> None: ...

class SignedICDCIdentityList(_message.Message):
    __slots__ = ("details", "signature")
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    signature: bytes
    def __init__(self, details: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...
