from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MultiDevice(_message.Message):
    __slots__ = ("payload", "metadata")
    class Metadata(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Payload(_message.Message):
        __slots__ = ("applicationData", "signal")
        APPLICATIONDATA_FIELD_NUMBER: _ClassVar[int]
        SIGNAL_FIELD_NUMBER: _ClassVar[int]
        applicationData: MultiDevice.ApplicationData
        signal: MultiDevice.Signal
        def __init__(self, applicationData: _Optional[_Union[MultiDevice.ApplicationData, _Mapping]] = ..., signal: _Optional[_Union[MultiDevice.Signal, _Mapping]] = ...) -> None: ...
    class ApplicationData(_message.Message):
        __slots__ = ("appStateSyncKeyShare", "appStateSyncKeyRequest")
        class AppStateSyncKeyRequestMessage(_message.Message):
            __slots__ = ("keyIDs",)
            KEYIDS_FIELD_NUMBER: _ClassVar[int]
            keyIDs: _containers.RepeatedCompositeFieldContainer[MultiDevice.ApplicationData.AppStateSyncKeyId]
            def __init__(self, keyIDs: _Optional[_Iterable[_Union[MultiDevice.ApplicationData.AppStateSyncKeyId, _Mapping]]] = ...) -> None: ...
        class AppStateSyncKeyShareMessage(_message.Message):
            __slots__ = ("keys",)
            KEYS_FIELD_NUMBER: _ClassVar[int]
            keys: _containers.RepeatedCompositeFieldContainer[MultiDevice.ApplicationData.AppStateSyncKey]
            def __init__(self, keys: _Optional[_Iterable[_Union[MultiDevice.ApplicationData.AppStateSyncKey, _Mapping]]] = ...) -> None: ...
        class AppStateSyncKey(_message.Message):
            __slots__ = ("keyID", "keyData")
            class AppStateSyncKeyData(_message.Message):
                __slots__ = ("keyData", "fingerprint", "timestamp")
                class AppStateSyncKeyFingerprint(_message.Message):
                    __slots__ = ("rawID", "currentIndex", "deviceIndexes")
                    RAWID_FIELD_NUMBER: _ClassVar[int]
                    CURRENTINDEX_FIELD_NUMBER: _ClassVar[int]
                    DEVICEINDEXES_FIELD_NUMBER: _ClassVar[int]
                    rawID: int
                    currentIndex: int
                    deviceIndexes: _containers.RepeatedScalarFieldContainer[int]
                    def __init__(self, rawID: _Optional[int] = ..., currentIndex: _Optional[int] = ..., deviceIndexes: _Optional[_Iterable[int]] = ...) -> None: ...
                KEYDATA_FIELD_NUMBER: _ClassVar[int]
                FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
                TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                keyData: bytes
                fingerprint: MultiDevice.ApplicationData.AppStateSyncKey.AppStateSyncKeyData.AppStateSyncKeyFingerprint
                timestamp: int
                def __init__(self, keyData: _Optional[bytes] = ..., fingerprint: _Optional[_Union[MultiDevice.ApplicationData.AppStateSyncKey.AppStateSyncKeyData.AppStateSyncKeyFingerprint, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...
            KEYID_FIELD_NUMBER: _ClassVar[int]
            KEYDATA_FIELD_NUMBER: _ClassVar[int]
            keyID: MultiDevice.ApplicationData.AppStateSyncKeyId
            keyData: MultiDevice.ApplicationData.AppStateSyncKey.AppStateSyncKeyData
            def __init__(self, keyID: _Optional[_Union[MultiDevice.ApplicationData.AppStateSyncKeyId, _Mapping]] = ..., keyData: _Optional[_Union[MultiDevice.ApplicationData.AppStateSyncKey.AppStateSyncKeyData, _Mapping]] = ...) -> None: ...
        class AppStateSyncKeyId(_message.Message):
            __slots__ = ("keyID",)
            KEYID_FIELD_NUMBER: _ClassVar[int]
            keyID: bytes
            def __init__(self, keyID: _Optional[bytes] = ...) -> None: ...
        APPSTATESYNCKEYSHARE_FIELD_NUMBER: _ClassVar[int]
        APPSTATESYNCKEYREQUEST_FIELD_NUMBER: _ClassVar[int]
        appStateSyncKeyShare: MultiDevice.ApplicationData.AppStateSyncKeyShareMessage
        appStateSyncKeyRequest: MultiDevice.ApplicationData.AppStateSyncKeyRequestMessage
        def __init__(self, appStateSyncKeyShare: _Optional[_Union[MultiDevice.ApplicationData.AppStateSyncKeyShareMessage, _Mapping]] = ..., appStateSyncKeyRequest: _Optional[_Union[MultiDevice.ApplicationData.AppStateSyncKeyRequestMessage, _Mapping]] = ...) -> None: ...
    class Signal(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    payload: MultiDevice.Payload
    metadata: MultiDevice.Metadata
    def __init__(self, payload: _Optional[_Union[MultiDevice.Payload, _Mapping]] = ..., metadata: _Optional[_Union[MultiDevice.Metadata, _Mapping]] = ...) -> None: ...
