from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MessageTransport(_message.Message):
    __slots__ = ("payload", "protocol")
    class Payload(_message.Message):
        __slots__ = ("applicationPayload", "futureProof")
        APPLICATIONPAYLOAD_FIELD_NUMBER: _ClassVar[int]
        FUTUREPROOF_FIELD_NUMBER: _ClassVar[int]
        applicationPayload: _WACommon_pb2.SubProtocol
        futureProof: _WACommon_pb2.FutureProofBehavior
        def __init__(self, applicationPayload: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., futureProof: _Optional[_Union[_WACommon_pb2.FutureProofBehavior, str]] = ...) -> None: ...
    class Protocol(_message.Message):
        __slots__ = ("integral", "ancillary")
        class Ancillary(_message.Message):
            __slots__ = ("skdm", "deviceListMetadata", "icdc", "backupDirective")
            class BackupDirective(_message.Message):
                __slots__ = ("messageID", "actionType", "supplementalKey")
                class ActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                    __slots__ = ()
                    NOOP: _ClassVar[MessageTransport.Protocol.Ancillary.BackupDirective.ActionType]
                    UPSERT: _ClassVar[MessageTransport.Protocol.Ancillary.BackupDirective.ActionType]
                    DELETE: _ClassVar[MessageTransport.Protocol.Ancillary.BackupDirective.ActionType]
                    UPSERT_AND_DELETE: _ClassVar[MessageTransport.Protocol.Ancillary.BackupDirective.ActionType]
                NOOP: MessageTransport.Protocol.Ancillary.BackupDirective.ActionType
                UPSERT: MessageTransport.Protocol.Ancillary.BackupDirective.ActionType
                DELETE: MessageTransport.Protocol.Ancillary.BackupDirective.ActionType
                UPSERT_AND_DELETE: MessageTransport.Protocol.Ancillary.BackupDirective.ActionType
                MESSAGEID_FIELD_NUMBER: _ClassVar[int]
                ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
                SUPPLEMENTALKEY_FIELD_NUMBER: _ClassVar[int]
                messageID: str
                actionType: MessageTransport.Protocol.Ancillary.BackupDirective.ActionType
                supplementalKey: str
                def __init__(self, messageID: _Optional[str] = ..., actionType: _Optional[_Union[MessageTransport.Protocol.Ancillary.BackupDirective.ActionType, str]] = ..., supplementalKey: _Optional[str] = ...) -> None: ...
            class ICDCParticipantDevices(_message.Message):
                __slots__ = ("senderIdentity", "recipientIdentities", "recipientUserJIDs")
                class ICDCIdentityListDescription(_message.Message):
                    __slots__ = ("seq", "signingDevice", "unknownDevices", "unknownDeviceIDs")
                    SEQ_FIELD_NUMBER: _ClassVar[int]
                    SIGNINGDEVICE_FIELD_NUMBER: _ClassVar[int]
                    UNKNOWNDEVICES_FIELD_NUMBER: _ClassVar[int]
                    UNKNOWNDEVICEIDS_FIELD_NUMBER: _ClassVar[int]
                    seq: int
                    signingDevice: bytes
                    unknownDevices: _containers.RepeatedScalarFieldContainer[bytes]
                    unknownDeviceIDs: _containers.RepeatedScalarFieldContainer[int]
                    def __init__(self, seq: _Optional[int] = ..., signingDevice: _Optional[bytes] = ..., unknownDevices: _Optional[_Iterable[bytes]] = ..., unknownDeviceIDs: _Optional[_Iterable[int]] = ...) -> None: ...
                SENDERIDENTITY_FIELD_NUMBER: _ClassVar[int]
                RECIPIENTIDENTITIES_FIELD_NUMBER: _ClassVar[int]
                RECIPIENTUSERJIDS_FIELD_NUMBER: _ClassVar[int]
                senderIdentity: MessageTransport.Protocol.Ancillary.ICDCParticipantDevices.ICDCIdentityListDescription
                recipientIdentities: _containers.RepeatedCompositeFieldContainer[MessageTransport.Protocol.Ancillary.ICDCParticipantDevices.ICDCIdentityListDescription]
                recipientUserJIDs: _containers.RepeatedScalarFieldContainer[str]
                def __init__(self, senderIdentity: _Optional[_Union[MessageTransport.Protocol.Ancillary.ICDCParticipantDevices.ICDCIdentityListDescription, _Mapping]] = ..., recipientIdentities: _Optional[_Iterable[_Union[MessageTransport.Protocol.Ancillary.ICDCParticipantDevices.ICDCIdentityListDescription, _Mapping]]] = ..., recipientUserJIDs: _Optional[_Iterable[str]] = ...) -> None: ...
            class SenderKeyDistributionMessage(_message.Message):
                __slots__ = ("groupID", "axolotlSenderKeyDistributionMessage")
                GROUPID_FIELD_NUMBER: _ClassVar[int]
                AXOLOTLSENDERKEYDISTRIBUTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
                groupID: str
                axolotlSenderKeyDistributionMessage: bytes
                def __init__(self, groupID: _Optional[str] = ..., axolotlSenderKeyDistributionMessage: _Optional[bytes] = ...) -> None: ...
            SKDM_FIELD_NUMBER: _ClassVar[int]
            DEVICELISTMETADATA_FIELD_NUMBER: _ClassVar[int]
            ICDC_FIELD_NUMBER: _ClassVar[int]
            BACKUPDIRECTIVE_FIELD_NUMBER: _ClassVar[int]
            skdm: MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage
            deviceListMetadata: DeviceListMetadata
            icdc: MessageTransport.Protocol.Ancillary.ICDCParticipantDevices
            backupDirective: MessageTransport.Protocol.Ancillary.BackupDirective
            def __init__(self, skdm: _Optional[_Union[MessageTransport.Protocol.Ancillary.SenderKeyDistributionMessage, _Mapping]] = ..., deviceListMetadata: _Optional[_Union[DeviceListMetadata, _Mapping]] = ..., icdc: _Optional[_Union[MessageTransport.Protocol.Ancillary.ICDCParticipantDevices, _Mapping]] = ..., backupDirective: _Optional[_Union[MessageTransport.Protocol.Ancillary.BackupDirective, _Mapping]] = ...) -> None: ...
        class Integral(_message.Message):
            __slots__ = ("padding", "DSM")
            class DeviceSentMessage(_message.Message):
                __slots__ = ("destinationJID", "phash")
                DESTINATIONJID_FIELD_NUMBER: _ClassVar[int]
                PHASH_FIELD_NUMBER: _ClassVar[int]
                destinationJID: str
                phash: str
                def __init__(self, destinationJID: _Optional[str] = ..., phash: _Optional[str] = ...) -> None: ...
            PADDING_FIELD_NUMBER: _ClassVar[int]
            DSM_FIELD_NUMBER: _ClassVar[int]
            padding: bytes
            DSM: MessageTransport.Protocol.Integral.DeviceSentMessage
            def __init__(self, padding: _Optional[bytes] = ..., DSM: _Optional[_Union[MessageTransport.Protocol.Integral.DeviceSentMessage, _Mapping]] = ...) -> None: ...
        INTEGRAL_FIELD_NUMBER: _ClassVar[int]
        ANCILLARY_FIELD_NUMBER: _ClassVar[int]
        integral: MessageTransport.Protocol.Integral
        ancillary: MessageTransport.Protocol.Ancillary
        def __init__(self, integral: _Optional[_Union[MessageTransport.Protocol.Integral, _Mapping]] = ..., ancillary: _Optional[_Union[MessageTransport.Protocol.Ancillary, _Mapping]] = ...) -> None: ...
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    payload: MessageTransport.Payload
    protocol: MessageTransport.Protocol
    def __init__(self, payload: _Optional[_Union[MessageTransport.Payload, _Mapping]] = ..., protocol: _Optional[_Union[MessageTransport.Protocol, _Mapping]] = ...) -> None: ...

class DeviceListMetadata(_message.Message):
    __slots__ = ("senderKeyHash", "senderTimestamp", "recipientKeyHash", "recipientTimestamp")
    SENDERKEYHASH_FIELD_NUMBER: _ClassVar[int]
    SENDERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTKEYHASH_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    senderKeyHash: bytes
    senderTimestamp: int
    recipientKeyHash: bytes
    recipientTimestamp: int
    def __init__(self, senderKeyHash: _Optional[bytes] = ..., senderTimestamp: _Optional[int] = ..., recipientKeyHash: _Optional[bytes] = ..., recipientTimestamp: _Optional[int] = ...) -> None: ...
