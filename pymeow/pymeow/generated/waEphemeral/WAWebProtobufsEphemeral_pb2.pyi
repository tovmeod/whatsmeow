from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class EphemeralSetting(_message.Message):
    __slots__ = ("duration", "timestamp")
    DURATION_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    duration: int
    timestamp: int
    def __init__(self, duration: _Optional[int] = ..., timestamp: _Optional[int] = ...) -> None: ...
