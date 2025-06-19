from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WAMediaTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("fileLength", "mimetype", "thumbnail", "objectID")
        class Thumbnail(_message.Message):
            __slots__ = ("JPEGThumbnail", "downloadableThumbnail", "thumbnailWidth", "thumbnailHeight")
            class DownloadableThumbnail(_message.Message):
                __slots__ = ("fileSHA256", "fileEncSHA256", "directPath", "mediaKey", "mediaKeyTimestamp", "objectID", "thumbnailScansSidecar", "thumbnailScanLengths")
                FILESHA256_FIELD_NUMBER: _ClassVar[int]
                FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
                DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                OBJECTID_FIELD_NUMBER: _ClassVar[int]
                THUMBNAILSCANSSIDECAR_FIELD_NUMBER: _ClassVar[int]
                THUMBNAILSCANLENGTHS_FIELD_NUMBER: _ClassVar[int]
                fileSHA256: bytes
                fileEncSHA256: bytes
                directPath: str
                mediaKey: bytes
                mediaKeyTimestamp: int
                objectID: str
                thumbnailScansSidecar: bytes
                thumbnailScanLengths: _containers.RepeatedScalarFieldContainer[int]
                def __init__(self, fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., objectID: _Optional[str] = ..., thumbnailScansSidecar: _Optional[bytes] = ..., thumbnailScanLengths: _Optional[_Iterable[int]] = ...) -> None: ...
            JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
            DOWNLOADABLETHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
            THUMBNAILWIDTH_FIELD_NUMBER: _ClassVar[int]
            THUMBNAILHEIGHT_FIELD_NUMBER: _ClassVar[int]
            JPEGThumbnail: bytes
            downloadableThumbnail: WAMediaTransport.Ancillary.Thumbnail.DownloadableThumbnail
            thumbnailWidth: int
            thumbnailHeight: int
            def __init__(self, JPEGThumbnail: _Optional[bytes] = ..., downloadableThumbnail: _Optional[_Union[WAMediaTransport.Ancillary.Thumbnail.DownloadableThumbnail, _Mapping]] = ..., thumbnailWidth: _Optional[int] = ..., thumbnailHeight: _Optional[int] = ...) -> None: ...
        FILELENGTH_FIELD_NUMBER: _ClassVar[int]
        MIMETYPE_FIELD_NUMBER: _ClassVar[int]
        THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        OBJECTID_FIELD_NUMBER: _ClassVar[int]
        fileLength: int
        mimetype: str
        thumbnail: WAMediaTransport.Ancillary.Thumbnail
        objectID: str
        def __init__(self, fileLength: _Optional[int] = ..., mimetype: _Optional[str] = ..., thumbnail: _Optional[_Union[WAMediaTransport.Ancillary.Thumbnail, _Mapping]] = ..., objectID: _Optional[str] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("fileSHA256", "mediaKey", "fileEncSHA256", "directPath", "mediaKeyTimestamp")
        FILESHA256_FIELD_NUMBER: _ClassVar[int]
        MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
        FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
        DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
        MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        fileSHA256: bytes
        mediaKey: bytes
        fileEncSHA256: bytes
        directPath: str
        mediaKeyTimestamp: int
        def __init__(self, fileSHA256: _Optional[bytes] = ..., mediaKey: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKeyTimestamp: _Optional[int] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: WAMediaTransport.Integral
    ancillary: WAMediaTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[WAMediaTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[WAMediaTransport.Ancillary, _Mapping]] = ...) -> None: ...

class ImageTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("height", "width", "scansSidecar", "scanLengths", "midQualityFileSHA256", "hdType", "memoriesConceptScores", "memoriesConceptIDs")
        class HdType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NONE: _ClassVar[ImageTransport.Ancillary.HdType]
            LQ_4K: _ClassVar[ImageTransport.Ancillary.HdType]
            HQ_4K: _ClassVar[ImageTransport.Ancillary.HdType]
        NONE: ImageTransport.Ancillary.HdType
        LQ_4K: ImageTransport.Ancillary.HdType
        HQ_4K: ImageTransport.Ancillary.HdType
        HEIGHT_FIELD_NUMBER: _ClassVar[int]
        WIDTH_FIELD_NUMBER: _ClassVar[int]
        SCANSSIDECAR_FIELD_NUMBER: _ClassVar[int]
        SCANLENGTHS_FIELD_NUMBER: _ClassVar[int]
        MIDQUALITYFILESHA256_FIELD_NUMBER: _ClassVar[int]
        HDTYPE_FIELD_NUMBER: _ClassVar[int]
        MEMORIESCONCEPTSCORES_FIELD_NUMBER: _ClassVar[int]
        MEMORIESCONCEPTIDS_FIELD_NUMBER: _ClassVar[int]
        height: int
        width: int
        scansSidecar: bytes
        scanLengths: _containers.RepeatedScalarFieldContainer[int]
        midQualityFileSHA256: bytes
        hdType: ImageTransport.Ancillary.HdType
        memoriesConceptScores: _containers.RepeatedScalarFieldContainer[float]
        memoriesConceptIDs: _containers.RepeatedScalarFieldContainer[int]
        def __init__(self, height: _Optional[int] = ..., width: _Optional[int] = ..., scansSidecar: _Optional[bytes] = ..., scanLengths: _Optional[_Iterable[int]] = ..., midQualityFileSHA256: _Optional[bytes] = ..., hdType: _Optional[_Union[ImageTransport.Ancillary.HdType, str]] = ..., memoriesConceptScores: _Optional[_Iterable[float]] = ..., memoriesConceptIDs: _Optional[_Iterable[int]] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("transport",)
        TRANSPORT_FIELD_NUMBER: _ClassVar[int]
        transport: WAMediaTransport
        def __init__(self, transport: _Optional[_Union[WAMediaTransport, _Mapping]] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: ImageTransport.Integral
    ancillary: ImageTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[ImageTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[ImageTransport.Ancillary, _Mapping]] = ...) -> None: ...

class VideoTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("seconds", "caption", "gifPlayback", "height", "width", "sidecar", "gifAttribution", "accessibilityLabel", "isHd")
        class Attribution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NONE: _ClassVar[VideoTransport.Ancillary.Attribution]
            GIPHY: _ClassVar[VideoTransport.Ancillary.Attribution]
            TENOR: _ClassVar[VideoTransport.Ancillary.Attribution]
        NONE: VideoTransport.Ancillary.Attribution
        GIPHY: VideoTransport.Ancillary.Attribution
        TENOR: VideoTransport.Ancillary.Attribution
        SECONDS_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        GIFPLAYBACK_FIELD_NUMBER: _ClassVar[int]
        HEIGHT_FIELD_NUMBER: _ClassVar[int]
        WIDTH_FIELD_NUMBER: _ClassVar[int]
        SIDECAR_FIELD_NUMBER: _ClassVar[int]
        GIFATTRIBUTION_FIELD_NUMBER: _ClassVar[int]
        ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
        ISHD_FIELD_NUMBER: _ClassVar[int]
        seconds: int
        caption: _WACommon_pb2.MessageText
        gifPlayback: bool
        height: int
        width: int
        sidecar: bytes
        gifAttribution: VideoTransport.Ancillary.Attribution
        accessibilityLabel: str
        isHd: bool
        def __init__(self, seconds: _Optional[int] = ..., caption: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., gifPlayback: bool = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., sidecar: _Optional[bytes] = ..., gifAttribution: _Optional[_Union[VideoTransport.Ancillary.Attribution, str]] = ..., accessibilityLabel: _Optional[str] = ..., isHd: bool = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("transport",)
        TRANSPORT_FIELD_NUMBER: _ClassVar[int]
        transport: WAMediaTransport
        def __init__(self, transport: _Optional[_Union[WAMediaTransport, _Mapping]] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: VideoTransport.Integral
    ancillary: VideoTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[VideoTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[VideoTransport.Ancillary, _Mapping]] = ...) -> None: ...

class AudioTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("seconds", "avatarAudio")
        class AvatarAudio(_message.Message):
            __slots__ = ("poseID", "avatarAnimations")
            class AnimationsType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                TALKING_A: _ClassVar[AudioTransport.Ancillary.AvatarAudio.AnimationsType]
                IDLE_A: _ClassVar[AudioTransport.Ancillary.AvatarAudio.AnimationsType]
                TALKING_B: _ClassVar[AudioTransport.Ancillary.AvatarAudio.AnimationsType]
                IDLE_B: _ClassVar[AudioTransport.Ancillary.AvatarAudio.AnimationsType]
                BACKGROUND: _ClassVar[AudioTransport.Ancillary.AvatarAudio.AnimationsType]
            TALKING_A: AudioTransport.Ancillary.AvatarAudio.AnimationsType
            IDLE_A: AudioTransport.Ancillary.AvatarAudio.AnimationsType
            TALKING_B: AudioTransport.Ancillary.AvatarAudio.AnimationsType
            IDLE_B: AudioTransport.Ancillary.AvatarAudio.AnimationsType
            BACKGROUND: AudioTransport.Ancillary.AvatarAudio.AnimationsType
            class DownloadableAvatarAnimations(_message.Message):
                __slots__ = ("fileSHA256", "fileEncSHA256", "directPath", "mediaKey", "mediaKeyTimestamp", "objectID", "animationsType")
                FILESHA256_FIELD_NUMBER: _ClassVar[int]
                FILEENCSHA256_FIELD_NUMBER: _ClassVar[int]
                DIRECTPATH_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEY_FIELD_NUMBER: _ClassVar[int]
                MEDIAKEYTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                OBJECTID_FIELD_NUMBER: _ClassVar[int]
                ANIMATIONSTYPE_FIELD_NUMBER: _ClassVar[int]
                fileSHA256: bytes
                fileEncSHA256: bytes
                directPath: str
                mediaKey: bytes
                mediaKeyTimestamp: int
                objectID: str
                animationsType: AudioTransport.Ancillary.AvatarAudio.AnimationsType
                def __init__(self, fileSHA256: _Optional[bytes] = ..., fileEncSHA256: _Optional[bytes] = ..., directPath: _Optional[str] = ..., mediaKey: _Optional[bytes] = ..., mediaKeyTimestamp: _Optional[int] = ..., objectID: _Optional[str] = ..., animationsType: _Optional[_Union[AudioTransport.Ancillary.AvatarAudio.AnimationsType, str]] = ...) -> None: ...
            POSEID_FIELD_NUMBER: _ClassVar[int]
            AVATARANIMATIONS_FIELD_NUMBER: _ClassVar[int]
            poseID: int
            avatarAnimations: _containers.RepeatedCompositeFieldContainer[AudioTransport.Ancillary.AvatarAudio.DownloadableAvatarAnimations]
            def __init__(self, poseID: _Optional[int] = ..., avatarAnimations: _Optional[_Iterable[_Union[AudioTransport.Ancillary.AvatarAudio.DownloadableAvatarAnimations, _Mapping]]] = ...) -> None: ...
        SECONDS_FIELD_NUMBER: _ClassVar[int]
        AVATARAUDIO_FIELD_NUMBER: _ClassVar[int]
        seconds: int
        avatarAudio: AudioTransport.Ancillary.AvatarAudio
        def __init__(self, seconds: _Optional[int] = ..., avatarAudio: _Optional[_Union[AudioTransport.Ancillary.AvatarAudio, _Mapping]] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("transport", "audioFormat")
        class AudioFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[AudioTransport.Integral.AudioFormat]
            OPUS: _ClassVar[AudioTransport.Integral.AudioFormat]
        UNKNOWN: AudioTransport.Integral.AudioFormat
        OPUS: AudioTransport.Integral.AudioFormat
        TRANSPORT_FIELD_NUMBER: _ClassVar[int]
        AUDIOFORMAT_FIELD_NUMBER: _ClassVar[int]
        transport: WAMediaTransport
        audioFormat: AudioTransport.Integral.AudioFormat
        def __init__(self, transport: _Optional[_Union[WAMediaTransport, _Mapping]] = ..., audioFormat: _Optional[_Union[AudioTransport.Integral.AudioFormat, str]] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: AudioTransport.Integral
    ancillary: AudioTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[AudioTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[AudioTransport.Ancillary, _Mapping]] = ...) -> None: ...

class DocumentTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("pageCount",)
        PAGECOUNT_FIELD_NUMBER: _ClassVar[int]
        pageCount: int
        def __init__(self, pageCount: _Optional[int] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("transport",)
        TRANSPORT_FIELD_NUMBER: _ClassVar[int]
        transport: WAMediaTransport
        def __init__(self, transport: _Optional[_Union[WAMediaTransport, _Mapping]] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: DocumentTransport.Integral
    ancillary: DocumentTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[DocumentTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[DocumentTransport.Ancillary, _Mapping]] = ...) -> None: ...

class StickerTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("pageCount", "height", "width", "firstFrameLength", "firstFrameSidecar", "mustacheText", "isThirdParty", "receiverFetchID", "accessibilityLabel")
        PAGECOUNT_FIELD_NUMBER: _ClassVar[int]
        HEIGHT_FIELD_NUMBER: _ClassVar[int]
        WIDTH_FIELD_NUMBER: _ClassVar[int]
        FIRSTFRAMELENGTH_FIELD_NUMBER: _ClassVar[int]
        FIRSTFRAMESIDECAR_FIELD_NUMBER: _ClassVar[int]
        MUSTACHETEXT_FIELD_NUMBER: _ClassVar[int]
        ISTHIRDPARTY_FIELD_NUMBER: _ClassVar[int]
        RECEIVERFETCHID_FIELD_NUMBER: _ClassVar[int]
        ACCESSIBILITYLABEL_FIELD_NUMBER: _ClassVar[int]
        pageCount: int
        height: int
        width: int
        firstFrameLength: int
        firstFrameSidecar: bytes
        mustacheText: str
        isThirdParty: bool
        receiverFetchID: str
        accessibilityLabel: str
        def __init__(self, pageCount: _Optional[int] = ..., height: _Optional[int] = ..., width: _Optional[int] = ..., firstFrameLength: _Optional[int] = ..., firstFrameSidecar: _Optional[bytes] = ..., mustacheText: _Optional[str] = ..., isThirdParty: bool = ..., receiverFetchID: _Optional[str] = ..., accessibilityLabel: _Optional[str] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("transport", "isAnimated", "receiverFetchID")
        TRANSPORT_FIELD_NUMBER: _ClassVar[int]
        ISANIMATED_FIELD_NUMBER: _ClassVar[int]
        RECEIVERFETCHID_FIELD_NUMBER: _ClassVar[int]
        transport: WAMediaTransport
        isAnimated: bool
        receiverFetchID: str
        def __init__(self, transport: _Optional[_Union[WAMediaTransport, _Mapping]] = ..., isAnimated: bool = ..., receiverFetchID: _Optional[str] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: StickerTransport.Integral
    ancillary: StickerTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[StickerTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[StickerTransport.Ancillary, _Mapping]] = ...) -> None: ...

class ContactTransport(_message.Message):
    __slots__ = ("integral", "ancillary")
    class Ancillary(_message.Message):
        __slots__ = ("displayName",)
        DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
        displayName: str
        def __init__(self, displayName: _Optional[str] = ...) -> None: ...
    class Integral(_message.Message):
        __slots__ = ("vcard", "downloadableVcard")
        VCARD_FIELD_NUMBER: _ClassVar[int]
        DOWNLOADABLEVCARD_FIELD_NUMBER: _ClassVar[int]
        vcard: str
        downloadableVcard: WAMediaTransport
        def __init__(self, vcard: _Optional[str] = ..., downloadableVcard: _Optional[_Union[WAMediaTransport, _Mapping]] = ...) -> None: ...
    INTEGRAL_FIELD_NUMBER: _ClassVar[int]
    ANCILLARY_FIELD_NUMBER: _ClassVar[int]
    integral: ContactTransport.Integral
    ancillary: ContactTransport.Ancillary
    def __init__(self, integral: _Optional[_Union[ContactTransport.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[ContactTransport.Ancillary, _Mapping]] = ...) -> None: ...
