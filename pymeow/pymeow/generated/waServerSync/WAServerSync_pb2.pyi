from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SyncdMutation(_message.Message):
    __slots__ = ("operation", "record")
    class SyncdOperation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SET: _ClassVar[SyncdMutation.SyncdOperation]
        REMOVE: _ClassVar[SyncdMutation.SyncdOperation]
    SET: SyncdMutation.SyncdOperation
    REMOVE: SyncdMutation.SyncdOperation
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_FIELD_NUMBER: _ClassVar[int]
    operation: SyncdMutation.SyncdOperation
    record: SyncdRecord
    def __init__(self, operation: _Optional[_Union[SyncdMutation.SyncdOperation, str]] = ..., record: _Optional[_Union[SyncdRecord, _Mapping]] = ...) -> None: ...

class SyncdVersion(_message.Message):
    __slots__ = ("version",)
    VERSION_FIELD_NUMBER: _ClassVar[int]
    version: int
    def __init__(self, version: _Optional[int] = ...) -> None: ...

class ExitCode(_message.Message):
    __slots__ = ("code", "text")
    CODE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    code: int
    text: str
    def __init__(self, code: _Optional[int] = ..., text: _Optional[str] = ...) -> None: ...

class SyncdIndex(_message.Message):
    __slots__ = ("blob",)
    BLOB_FIELD_NUMBER: _ClassVar[int]
    blob: bytes
    def __init__(self, blob: _Optional[bytes] = ...) -> None: ...

class SyncdValue(_message.Message):
    __slots__ = ("blob",)
    BLOB_FIELD_NUMBER: _ClassVar[int]
    blob: bytes
    def __init__(self, blob: _Optional[bytes] = ...) -> None: ...

class KeyId(_message.Message):
    __slots__ = ("ID",)
    ID_FIELD_NUMBER: _ClassVar[int]
    ID: bytes
    def __init__(self, ID: _Optional[bytes] = ...) -> None: ...

class SyncdRecord(_message.Message):
    __slots__ = ("index", "value", "keyID")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    index: SyncdIndex
    value: SyncdValue
    keyID: KeyId
    def __init__(self, index: _Optional[_Union[SyncdIndex, _Mapping]] = ..., value: _Optional[_Union[SyncdValue, _Mapping]] = ..., keyID: _Optional[_Union[KeyId, _Mapping]] = ...) -> None: ...

class ExternalBlobReference(_message.Message):
    __slots__ = ("mediaKey", "directPath", "handle", "fileSizeBytes", "fileSHA256", "fileEncSHA256")
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    FILESIZEBYTES_FIELD_NUMBER: _ClassVar[int]
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    mediaKey: bytes
    directPath: str
    handle: str
    fileSizeBytes: int
    fileSHA256: bytes
    fileEncSHA256: bytes
    def __init__(self, mediaKey: _Optional[bytes] = ..., directPath: _Optional[str] = ..., handle: _Optional[str] = ..., fileSizeBytes: _Optional[int] = ..., fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ...) -> None: ...

class SyncdSnapshot(_message.Message):
    __slots__ = ("version", "records", "mac", "keyID")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    version: SyncdVersion
    records: _containers.RepeatedCompositeFieldContainer[SyncdRecord]
    mac: bytes
    keyID: KeyId
    def __init__(self, version: _Optional[_Union[SyncdVersion, _Mapping]] = ..., records: _Optional[_Iterable[_Union[SyncdRecord, _Mapping]]] = ..., mac: _Optional[bytes] = ..., keyID: _Optional[_Union[KeyId, _Mapping]] = ...) -> None: ...

class SyncdMutations(_message.Message):
    __slots__ = ("mutations",)
    MUTATIONS_FIELD_NUMBER: _ClassVar[int]
    mutations: _containers.RepeatedCompositeFieldContainer[SyncdMutation]
    def __init__(self, mutations: _Optional[_Iterable[_Union[SyncdMutation, _Mapping]]] = ...) -> None: ...

class SyncdPatch(_message.Message):
    __slots__ = ("version", "mutations", "externalMutations", "snapshotMAC", "patchMAC", "keyID", "exitCode", "deviceIndex", "clientDebugData")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    MUTATIONS_FIELD_NUMBER: _ClassVar[int]
    EXTERNALMUTATIONS_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOTMAC_FIELD_NUMBER: _ClassVar[int]
    PATCHMAC_FIELD_NUMBER: _ClassVar[int]
    KEYID_FIELD_NUMBER: _ClassVar[int]
    EXITCODE_FIELD_NUMBER: _ClassVar[int]
    DEVICEINDEX_FIELD_NUMBER: _ClassVar[int]
    CLIENTDEBUGDATA_FIELD_NUMBER: _ClassVar[int]
    version: SyncdVersion
    mutations: _containers.RepeatedCompositeFieldContainer[SyncdMutation]
    externalMutations: ExternalBlobReference
    snapshotMAC: bytes
    patchMAC: bytes
    keyID: KeyId
    exitCode: ExitCode
    deviceIndex: int
    clientDebugData: bytes
    def __init__(self, version: _Optional[_Union[SyncdVersion, _Mapping]] = ..., mutations: _Optional[_Iterable[_Union[SyncdMutation, _Mapping]]] = ..., externalMutations: _Optional[_Union[ExternalBlobReference, _Mapping]] = ..., snapshotMAC: _Optional[bytes] = ..., patchMAC: _Optional[bytes] = ..., keyID: _Optional[_Union[KeyId, _Mapping]] = ..., exitCode: _Optional[_Union[ExitCode, _Mapping]] = ..., deviceIndex: _Optional[int] = ..., clientDebugData: _Optional[bytes] = ...) -> None: ...
