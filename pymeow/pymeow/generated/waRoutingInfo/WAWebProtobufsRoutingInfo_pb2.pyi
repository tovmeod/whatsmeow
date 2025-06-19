from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class RoutingInfo(_message.Message):
    __slots__ = ("regionID", "clusterID", "taskID", "debug", "tcpBbr", "tcpKeepalive")
    REGIONID_FIELD_NUMBER: _ClassVar[int]
    CLUSTERID_FIELD_NUMBER: _ClassVar[int]
    TASKID_FIELD_NUMBER: _ClassVar[int]
    DEBUG_FIELD_NUMBER: _ClassVar[int]
    TCPBBR_FIELD_NUMBER: _ClassVar[int]
    TCPKEEPALIVE_FIELD_NUMBER: _ClassVar[int]
    regionID: _containers.RepeatedScalarFieldContainer[int]
    clusterID: _containers.RepeatedScalarFieldContainer[int]
    taskID: int
    debug: bool
    tcpBbr: bool
    tcpKeepalive: bool
    def __init__(self, regionID: _Optional[_Iterable[int]] = ..., clusterID: _Optional[_Iterable[int]] = ..., taskID: _Optional[int] = ..., debug: bool = ..., tcpBbr: bool = ..., tcpKeepalive: bool = ...) -> None: ...
