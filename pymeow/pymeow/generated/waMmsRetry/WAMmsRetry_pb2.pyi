from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MediaRetryNotification(_message.Message):
    __slots__ = ("stanzaID", "directPath", "result", "messageSecret")
    class ResultType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        GENERAL_ERROR: _ClassVar[MediaRetryNotification.ResultType]
        SUCCESS: _ClassVar[MediaRetryNotification.ResultType]
        NOT_FOUND: _ClassVar[MediaRetryNotification.ResultType]
        DECRYPTION_ERROR: _ClassVar[MediaRetryNotification.ResultType]
    GENERAL_ERROR: MediaRetryNotification.ResultType
    SUCCESS: MediaRetryNotification.ResultType
    NOT_FOUND: MediaRetryNotification.ResultType
    DECRYPTION_ERROR: MediaRetryNotification.ResultType
    STANZAID_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    MESSAGESECRET_FIELD_NUMBER: _ClassVar[int]
    stanzaID: str
    directPath: str
    result: MediaRetryNotification.ResultType
    messageSecret: bytes
    def __init__(self, stanzaID: _Optional[str] = ..., directPath: _Optional[str] = ..., result: _Optional[_Union[MediaRetryNotification.ResultType, str]] = ..., messageSecret: _Optional[bytes] = ...) -> None: ...

class ServerErrorReceipt(_message.Message):
    __slots__ = ("stanzaID",)
    STANZAID_FIELD_NUMBER: _ClassVar[int]
    stanzaID: str
    def __init__(self, stanzaID: _Optional[str] = ...) -> None: ...
