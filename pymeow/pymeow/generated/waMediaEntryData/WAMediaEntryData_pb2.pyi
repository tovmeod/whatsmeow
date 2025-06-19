from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MediaEntry(_message.Message):
    __slots__ = ("fileSHA256", "mediaKey", "fileEncSHA256", "directPath", "mediaKeyTimestamp", "serverMediaType", "uploadToken", "validatedTimestamp", "sidecar", "objectID", "FBID", "downloadableThumbnail", "handle", "filename", "progressiveJPEGDetails", "size", "lastDownloadAttemptTimestamp")
    class ProgressiveJpegDetails(_message.Message):
        __slots__ = ("scanLengths", "sidecar")
        SCANLENGTHS_FIELD_NUMBER: _ClassVar[int]
        SIDECAR_FIELD_NUMBER: _ClassVar[int]
        scanLengths: _containers.RepeatedScalarFieldContainer[int]
        sidecar: bytes
        def __init__(self, scanLengths: _Optional[_Iterable[int]] = ..., sidecar: _Optional[bytes] = ...) -> None: ...
    class DownloadableThumbnail(_message.Message):
        __slots__ = ("fileSHA256", "fileEncSHA256", "directPath", "mediaKey", "mediaKeyTimestamp", "objectID")
        FILESHA256_FIELD_NUMBER: _ClassVar[int]
        FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
        DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
        MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
        MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        OBJECTID_FIELD_NUMBER: _ClassVar[int]
        fileSHA256: bytes
        fileEncSHA256: bytes
        directPath: str
        mediaKey: bytes
        mediaKeyTimestamp: int
        objectID: str
        def __init__(self, fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., objectID: _Optional[str] = ...) -> None: ...
    FILESHA256_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
    FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
    DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
    MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERMEDIATYPE_FIELD_NUMBER: _ClassVar[int]
    UPLOADTOKEN_FIELD_NUMBER: _ClassVar[int]
    VALIDATEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_FIELD_NUMBER: _ClassVar[int]
    OBJECTID_FIELD_NUMBER: _ClassVar[int]
    FBID_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADABLETHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    PROGRESSIVEJPEGDETAILS_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    LASTDOWNLOADATTEMPTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    fileSHA256: bytes
    mediaKey: bytes
    fileEncSHA256: bytes
    directPath: str
    mediaKeyTimestamp: int
    serverMediaType: str
    uploadToken: bytes
    validatedTimestamp: bytes
    sidecar: bytes
    objectID: str
    FBID: str
    downloadableThumbnail: MediaEntry.DownloadableThumbnail
    handle: str
    filename: str
    progressiveJPEGDetails: MediaEntry.ProgressiveJpegDetails
    size: int
    lastDownloadAttemptTimestamp: int
    def __init__(self, fileSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ..., serverMediaType: _Optional[str] = ..., uploadToken: _Optional[bytes] = ..., validatedTimestamp: _Optional[bytes] = ..., sidecar: _Optional[bytes] = ..., objectID: _Optional[str] = ..., FBID: _Optional[str] = ..., downloadableThumbnail: _Optional[_Union[MediaEntry.DownloadableThumbnail, _Mapping]] = ..., handle: _Optional[str] = ..., filename: _Optional[str] = ..., progressiveJPEGDetails: _Optional[_Union[MediaEntry.ProgressiveJpegDetails, _Mapping]] = ..., size: _Optional[int] = ..., lastDownloadAttemptTimestamp: _Optional[int] = ...) -> None: ...
