from waUserPassword import WAProtobufsUserPassword_pb2 as _WAProtobufsUserPassword_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ChatLockSettings(_message.Message):
    __slots__ = ("hideLockedChats", "secretCode")
    HIDELOCKEDCHATS_FIELD_NUMBER: _ClassVar[int]
    SECRETCODE_FIELD_NUMBER: _ClassVar[int]
    hideLockedChats: bool
    secretCode: _WAProtobufsUserPassword_pb2.UserPassword
    def __init__(self, hideLockedChats: bool = ..., secretCode: _Optional[_Union[_WAProtobufsUserPassword_pb2.UserPassword, _Mapping]] = ...) -> None: ...
