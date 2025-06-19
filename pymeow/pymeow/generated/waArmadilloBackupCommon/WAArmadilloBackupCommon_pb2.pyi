from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Subprotocol(_message.Message):
    __slots__ = ("payload", "version")
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    payload: bytes
    version: int
    def __init__(self, payload: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...
