from waArmadilloBackupCommon import WAArmadilloBackupCommon_pb2 as _WAArmadilloBackupCommon_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class BackupMessage(_message.Message):
    __slots__ = ("encryptedTransportMessage", "encryptedTransportEvent", "encryptedTransportLocallyTransformedMessage", "miTransportAdminMessage", "metadata")
    class Metadata(_message.Message):
        __slots__ = ("senderID", "messageID", "timestampMS", "frankingMetadata", "payloadVersion", "futureProofBehavior", "threadTypeTag")
        class FrankingMetadata(_message.Message):
            __slots__ = ("frankingTag", "reportingTag")
            FRANKINGTAG_FIELD_NUMBER: _ClassVar[int]
            REPORTINGTAG_FIELD_NUMBER: _ClassVar[int]
            frankingTag: bytes
            reportingTag: bytes
            def __init__(self, frankingTag: _Optional[bytes] = ..., reportingTag: _Optional[bytes] = ...) -> None: ...
        SENDERID_FIELD_NUMBER: _ClassVar[int]
        MESSAGEID_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
        FRANKINGMETADATA_FIELD_NUMBER: _ClassVar[int]
        PAYLOADVERSION_FIELD_NUMBER: _ClassVar[int]
        FUTUREPROOFBEHAVIOR_FIELD_NUMBER: _ClassVar[int]
        THREADTYPETAG_FIELD_NUMBER: _ClassVar[int]
        senderID: str
        messageID: str
        timestampMS: int
        frankingMetadata: BackupMessage.Metadata.FrankingMetadata
        payloadVersion: int
        futureProofBehavior: int
        threadTypeTag: int
        def __init__(self, senderID: _Optional[str] = ..., messageID: _Optional[str] = ..., timestampMS: _Optional[int] = ..., frankingMetadata: _Optional[_Union[BackupMessage.Metadata.FrankingMetadata, _Mapping]] = ..., payloadVersion: _Optional[int] = ..., futureProofBehavior: _Optional[int] = ..., threadTypeTag: _Optional[int] = ...) -> None: ...
    ENCRYPTEDTRANSPORTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTRANSPORTEVENT_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDTRANSPORTLOCALLYTRANSFORMEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    MITRANSPORTADMINMESSAGE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    encryptedTransportMessage: bytes
    encryptedTransportEvent: _WAArmadilloBackupCommon_pb2.Subprotocol
    encryptedTransportLocallyTransformedMessage: _WAArmadilloBackupCommon_pb2.Subprotocol
    miTransportAdminMessage: _WAArmadilloBackupCommon_pb2.Subprotocol
    metadata: BackupMessage.Metadata
    def __init__(self, encryptedTransportMessage: _Optional[bytes] = ..., encryptedTransportEvent: _Optional[_Union[_WAArmadilloBackupCommon_pb2.Subprotocol, _Mapping]] = ..., encryptedTransportLocallyTransformedMessage: _Optional[_Union[_WAArmadilloBackupCommon_pb2.Subprotocol, _Mapping]] = ..., miTransportAdminMessage: _Optional[_Union[_WAArmadilloBackupCommon_pb2.Subprotocol, _Mapping]] = ..., metadata: _Optional[_Union[BackupMessage.Metadata, _Mapping]] = ...) -> None: ...
