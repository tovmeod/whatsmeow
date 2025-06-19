from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LIDMigrationMapping(_message.Message):
    __slots__ = ("pn", "assignedLid", "latestLid")
    PN_FIELD_NUMBER: _ClassVar[int]
    ASSIGNEDLID_FIELD_NUMBER: _ClassVar[int]
    LATESTLID_FIELD_NUMBER: _ClassVar[int]
    pn: int
    assignedLid: int
    latestLid: int
    def __init__(self, pn: _Optional[int] = ..., assignedLid: _Optional[int] = ..., latestLid: _Optional[int] = ...) -> None: ...

class LIDMigrationMappingSyncPayload(_message.Message):
    __slots__ = ("pnToLidMappings", "chatDbMigrationTimestamp")
    PNTOLIDMAPPINGS_FIELD_NUMBER: _ClassVar[int]
    CHATDBMIGRATIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    pnToLidMappings: _containers.RepeatedCompositeFieldContainer[LIDMigrationMapping]
    chatDbMigrationTimestamp: int
    def __init__(self, pnToLidMappings: _Optional[_Iterable[_Union[LIDMigrationMapping, _Mapping]]] = ..., chatDbMigrationTimestamp: _Optional[int] = ...) -> None: ...
