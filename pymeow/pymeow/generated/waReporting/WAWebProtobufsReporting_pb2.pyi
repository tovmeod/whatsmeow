from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Reportable(_message.Message):
    __slots__ = ("minVersion", "maxVersion", "notReportableMinVersion", "never")
    MINVERSION_FIELD_NUMBER: _ClassVar[int]
    MAXVERSION_FIELD_NUMBER: _ClassVar[int]
    NOTREPORTABLEMINVERSION_FIELD_NUMBER: _ClassVar[int]
    NEVER_FIELD_NUMBER: _ClassVar[int]
    minVersion: int
    maxVersion: int
    notReportableMinVersion: int
    never: bool
    def __init__(self, minVersion: _Optional[int] = ..., maxVersion: _Optional[int] = ..., notReportableMinVersion: _Optional[int] = ..., never: bool = ...) -> None: ...

class Config(_message.Message):
    __slots__ = ("field", "version")
    class FieldEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Field
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Field, _Mapping]] = ...) -> None: ...
    FIELD_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    field: _containers.MessageMap[int, Field]
    version: int
    def __init__(self, field: _Optional[_Mapping[int, Field]] = ..., version: _Optional[int] = ...) -> None: ...

class Field(_message.Message):
    __slots__ = ("minVersion", "maxVersion", "notReportableMinVersion", "isMessage", "subfield")
    class SubfieldEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Field
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Field, _Mapping]] = ...) -> None: ...
    MINVERSION_FIELD_NUMBER: _ClassVar[int]
    MAXVERSION_FIELD_NUMBER: _ClassVar[int]
    NOTREPORTABLEMINVERSION_FIELD_NUMBER: _ClassVar[int]
    ISMESSAGE_FIELD_NUMBER: _ClassVar[int]
    SUBFIELD_FIELD_NUMBER: _ClassVar[int]
    minVersion: int
    maxVersion: int
    notReportableMinVersion: int
    isMessage: bool
    subfield: _containers.MessageMap[int, Field]
    def __init__(self, minVersion: _Optional[int] = ..., maxVersion: _Optional[int] = ..., notReportableMinVersion: _Optional[int] = ..., isMessage: bool = ..., subfield: _Optional[_Mapping[int, Field]] = ...) -> None: ...
