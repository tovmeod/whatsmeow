from ..waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MessageApplication(_message.Message):
    __slots__ = ("payload", "metadata")
    class Metadata(_message.Message):
        __slots__ = ("chatEphemeralSetting", "ephemeralSettingList", "ephemeralSharedSecret", "forwardingScore", "isForwarded", "businessMetadata", "frankingKey", "frankingVersion", "quotedMessage", "threadType", "readonlyMetadataDataclass", "groupID", "groupSize", "groupIndex", "botResponseID", "collapsibleID", "secondaryOtid")
        class ThreadType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DEFAULT: _ClassVar[MessageApplication.Metadata.ThreadType]
            VANISH_MODE: _ClassVar[MessageApplication.Metadata.ThreadType]
            DISAPPEARING_MESSAGES: _ClassVar[MessageApplication.Metadata.ThreadType]
        DEFAULT: MessageApplication.Metadata.ThreadType
        VANISH_MODE: MessageApplication.Metadata.ThreadType
        DISAPPEARING_MESSAGES: MessageApplication.Metadata.ThreadType
        class QuotedMessage(_message.Message):
            __slots__ = ("stanzaID", "remoteJID", "participant", "payload")
            STANZAID_FIELD_NUMBER: _ClassVar[int]
            REMOTEJID_FIELD_NUMBER: _ClassVar[int]
            PARTICIPANT_FIELD_NUMBER: _ClassVar[int]
            PAYLOAD_FIELD_NUMBER: _ClassVar[int]
            stanzaID: str
            remoteJID: str
            participant: str
            payload: MessageApplication.Payload
            def __init__(self, stanzaID: _Optional[str] = ..., remoteJID: _Optional[str] = ..., participant: _Optional[str] = ..., payload: _Optional[_Union[MessageApplication.Payload, _Mapping]] = ...) -> None: ...
        class EphemeralSettingMap(_message.Message):
            __slots__ = ("chatJID", "ephemeralSetting")
            CHATJID_FIELD_NUMBER: _ClassVar[int]
            EPHEMERALSETTING_FIELD_NUMBER: _ClassVar[int]
            chatJID: str
            ephemeralSetting: MessageApplication.EphemeralSetting
            def __init__(self, chatJID: _Optional[str] = ..., ephemeralSetting: _Optional[_Union[MessageApplication.EphemeralSetting, _Mapping]] = ...) -> None: ...
        CHATEPHEMERALSETTING_FIELD_NUMBER: _ClassVar[int]
        EPHEMERALSETTINGLIST_FIELD_NUMBER: _ClassVar[int]
        EPHEMERALSHAREDSECRET_FIELD_NUMBER: _ClassVar[int]
        FORWARDINGSCORE_FIELD_NUMBER: _ClassVar[int]
        ISFORWARDED_FIELD_NUMBER: _ClassVar[int]
        BUSINESSMETADATA_FIELD_NUMBER: _ClassVar[int]
        FRANKINGKEY_FIELD_NUMBER: _ClassVar[int]
        FRANKINGVERSION_FIELD_NUMBER: _ClassVar[int]
        QUOTEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
        THREADTYPE_FIELD_NUMBER: _ClassVar[int]
        READONLYMETADATADATACLASS_FIELD_NUMBER: _ClassVar[int]
        GROUPID_FIELD_NUMBER: _ClassVar[int]
        GROUPSIZE_FIELD_NUMBER: _ClassVar[int]
        GROUPINDEX_FIELD_NUMBER: _ClassVar[int]
        BOTRESPONSEID_FIELD_NUMBER: _ClassVar[int]
        COLLAPSIBLEID_FIELD_NUMBER: _ClassVar[int]
        SECONDARYOTID_FIELD_NUMBER: _ClassVar[int]
        chatEphemeralSetting: MessageApplication.EphemeralSetting
        ephemeralSettingList: MessageApplication.Metadata.EphemeralSettingMap
        ephemeralSharedSecret: bytes
        forwardingScore: int
        isForwarded: bool
        businessMetadata: _WACommon_pb2.SubProtocol
        frankingKey: bytes
        frankingVersion: int
        quotedMessage: MessageApplication.Metadata.QuotedMessage
        threadType: MessageApplication.Metadata.ThreadType
        readonlyMetadataDataclass: str
        groupID: str
        groupSize: int
        groupIndex: int
        botResponseID: str
        collapsibleID: str
        secondaryOtid: str
        def __init__(self, chatEphemeralSetting: _Optional[_Union[MessageApplication.EphemeralSetting, _Mapping]] = ..., ephemeralSettingList: _Optional[_Union[MessageApplication.Metadata.EphemeralSettingMap, _Mapping]] = ..., ephemeralSharedSecret: _Optional[bytes] = ..., forwardingScore: _Optional[int] = ..., isForwarded: bool = ..., businessMetadata: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., frankingKey: _Optional[bytes] = ..., frankingVersion: _Optional[int] = ..., quotedMessage: _Optional[_Union[MessageApplication.Metadata.QuotedMessage, _Mapping]] = ..., threadType: _Optional[_Union[MessageApplication.Metadata.ThreadType, str]] = ..., readonlyMetadataDataclass: _Optional[str] = ..., groupID: _Optional[str] = ..., groupSize: _Optional[int] = ..., groupIndex: _Optional[int] = ..., botResponseID: _Optional[str] = ..., collapsibleID: _Optional[str] = ..., secondaryOtid: _Optional[str] = ...) -> None: ...
    class Payload(_message.Message):
        __slots__ = ("coreContent", "signal", "applicationData", "subProtocol")
        CORECONTENT_FIELD_NUMBER: _ClassVar[int]
        SIGNAL_FIELD_NUMBER: _ClassVar[int]
        APPLICATIONDATA_FIELD_NUMBER: _ClassVar[int]
        SUBPROTOCOL_FIELD_NUMBER: _ClassVar[int]
        coreContent: MessageApplication.Content
        signal: MessageApplication.Signal
        applicationData: MessageApplication.ApplicationData
        subProtocol: MessageApplication.SubProtocolPayload
        def __init__(self, coreContent: _Optional[_Union[MessageApplication.Content, _Mapping]] = ..., signal: _Optional[_Union[MessageApplication.Signal, _Mapping]] = ..., applicationData: _Optional[_Union[MessageApplication.ApplicationData, _Mapping]] = ..., subProtocol: _Optional[_Union[MessageApplication.SubProtocolPayload, _Mapping]] = ...) -> None: ...
    class SubProtocolPayload(_message.Message):
        __slots__ = ("consumerMessage", "businessMessage", "paymentMessage", "multiDevice", "voip", "armadillo", "futureProof")
        CONSUMERMESSAGE_FIELD_NUMBER: _ClassVar[int]
        BUSINESSMESSAGE_FIELD_NUMBER: _ClassVar[int]
        PAYMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        MULTIDEVICE_FIELD_NUMBER: _ClassVar[int]
        VOIP_FIELD_NUMBER: _ClassVar[int]
        ARMADILLO_FIELD_NUMBER: _ClassVar[int]
        FUTUREPROOF_FIELD_NUMBER: _ClassVar[int]
        consumerMessage: _WACommon_pb2.SubProtocol
        businessMessage: _WACommon_pb2.SubProtocol
        paymentMessage: _WACommon_pb2.SubProtocol
        multiDevice: _WACommon_pb2.SubProtocol
        voip: _WACommon_pb2.SubProtocol
        armadillo: _WACommon_pb2.SubProtocol
        futureProof: _WACommon_pb2.FutureProofBehavior
        def __init__(self, consumerMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., businessMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., paymentMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., multiDevice: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., voip: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., armadillo: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., futureProof: _Optional[_Union[_WACommon_pb2.FutureProofBehavior, str]] = ...) -> None: ...
    class ApplicationData(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Signal(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Content(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class EphemeralSetting(_message.Message):
        __slots__ = ("ephemeralExpiration", "ephemeralSettingTimestamp", "ephemeralityType", "isEphemeralSettingReset")
        class EphemeralityType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[MessageApplication.EphemeralSetting.EphemeralityType]
            SEEN_ONCE: _ClassVar[MessageApplication.EphemeralSetting.EphemeralityType]
            SEEN_BASED_WITH_TIMER: _ClassVar[MessageApplication.EphemeralSetting.EphemeralityType]
            SEND_BASED_WITH_TIMER: _ClassVar[MessageApplication.EphemeralSetting.EphemeralityType]
        UNKNOWN: MessageApplication.EphemeralSetting.EphemeralityType
        SEEN_ONCE: MessageApplication.EphemeralSetting.EphemeralityType
        SEEN_BASED_WITH_TIMER: MessageApplication.EphemeralSetting.EphemeralityType
        SEND_BASED_WITH_TIMER: MessageApplication.EphemeralSetting.EphemeralityType
        EPHEMERALEXPIRATION_FIELD_NUMBER: _ClassVar[int]
        EPHEMERALSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        EPHEMERALITYTYPE_FIELD_NUMBER: _ClassVar[int]
        ISEPHEMERALSETTINGRESET_FIELD_NUMBER: _ClassVar[int]
        ephemeralExpiration: int
        ephemeralSettingTimestamp: int
        ephemeralityType: MessageApplication.EphemeralSetting.EphemeralityType
        isEphemeralSettingReset: bool
        def __init__(self, ephemeralExpiration: _Optional[int] = ..., ephemeralSettingTimestamp: _Optional[int] = ..., ephemeralityType: _Optional[_Union[MessageApplication.EphemeralSetting.EphemeralityType, str]] = ..., isEphemeralSettingReset: bool = ...) -> None: ...
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    payload: MessageApplication.Payload
    metadata: MessageApplication.Metadata
    def __init__(self, payload: _Optional[_Union[MessageApplication.Payload, _Mapping]] = ..., metadata: _Optional[_Union[MessageApplication.Metadata, _Mapping]] = ...) -> None: ...
