from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PositronDataSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESSAGES: _ClassVar[PositronDataSource]
    CHATS: _ClassVar[PositronDataSource]
    CONTACTS: _ClassVar[PositronDataSource]
    GROUP_METADATA: _ClassVar[PositronDataSource]
    GROUP_PARTICIPANTS: _ClassVar[PositronDataSource]
    REACTIONS: _ClassVar[PositronDataSource]
MESSAGES: PositronDataSource
CHATS: PositronDataSource
CONTACTS: PositronDataSource
GROUP_METADATA: PositronDataSource
GROUP_PARTICIPANTS: PositronDataSource
REACTIONS: PositronDataSource

class PositronMessage(_message.Message):
    __slots__ = ("timestamp", "type", "body", "ID", "JSON")
    class MsgKey(_message.Message):
        __slots__ = ("fromMe", "remote", "ID", "participant")
        FROMME_FIELD_NUMBER: _ClassVar[int]
        REMOTE_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        PARTICIPANT_FIELD_NUMBER: _ClassVar[int]
        fromMe: bool
        remote: PositronMessage.WID
        ID: str
        participant: PositronMessage.WID
        def __init__(self, fromMe: bool = ..., remote: _Optional[_Union[PositronMessage.WID, _Mapping]] = ..., ID: _Optional[str] = ..., participant: _Optional[_Union[PositronMessage.WID, _Mapping]] = ...) -> None: ...
    class WID(_message.Message):
        __slots__ = ("serialized",)
        SERIALIZED_FIELD_NUMBER: _ClassVar[int]
        serialized: str
        def __init__(self, serialized: _Optional[str] = ...) -> None: ...
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    type: str
    body: str
    ID: PositronMessage.MsgKey
    JSON: str
    def __init__(self, timestamp: _Optional[int] = ..., type: _Optional[str] = ..., body: _Optional[str] = ..., ID: _Optional[_Union[PositronMessage.MsgKey, _Mapping]] = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronChat(_message.Message):
    __slots__ = ("ID", "name", "timestamp", "unreadCount", "JSON")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    UNREADCOUNT_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    ID: str
    name: str
    timestamp: int
    unreadCount: int
    JSON: str
    def __init__(self, ID: _Optional[str] = ..., name: _Optional[str] = ..., timestamp: _Optional[int] = ..., unreadCount: _Optional[int] = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronContact(_message.Message):
    __slots__ = ("ID", "phoneNumber", "name", "isAddressBookContact", "JSON")
    ID_FIELD_NUMBER: _ClassVar[int]
    PHONENUMBER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ISADDRESSBOOKCONTACT_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    ID: str
    phoneNumber: str
    name: str
    isAddressBookContact: bool
    JSON: str
    def __init__(self, ID: _Optional[str] = ..., phoneNumber: _Optional[str] = ..., name: _Optional[str] = ..., isAddressBookContact: bool = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronGroupMetadata(_message.Message):
    __slots__ = ("ID", "subject", "JSON")
    ID_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    ID: str
    subject: str
    JSON: str
    def __init__(self, ID: _Optional[str] = ..., subject: _Optional[str] = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronGroupParticipants(_message.Message):
    __slots__ = ("ID", "participants", "JSON")
    ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    ID: str
    participants: _containers.RepeatedScalarFieldContainer[str]
    JSON: str
    def __init__(self, ID: _Optional[str] = ..., participants: _Optional[_Iterable[str]] = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronReaction(_message.Message):
    __slots__ = ("ID", "parentMsgKey", "reactionText", "timestamp", "senderUserJID", "JSON")
    ID_FIELD_NUMBER: _ClassVar[int]
    PARENTMSGKEY_FIELD_NUMBER: _ClassVar[int]
    REACTIONTEXT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SENDERUSERJID_FIELD_NUMBER: _ClassVar[int]
    JSON_FIELD_NUMBER: _ClassVar[int]
    ID: str
    parentMsgKey: str
    reactionText: str
    timestamp: int
    senderUserJID: str
    JSON: str
    def __init__(self, ID: _Optional[str] = ..., parentMsgKey: _Optional[str] = ..., reactionText: _Optional[str] = ..., timestamp: _Optional[int] = ..., senderUserJID: _Optional[str] = ..., JSON: _Optional[str] = ...) -> None: ...

class PositronData(_message.Message):
    __slots__ = ("dataSource", "messages", "chats", "contacts", "groupMetadata", "groupParticipants", "reactions")
    DATASOURCE_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    CHATS_FIELD_NUMBER: _ClassVar[int]
    CONTACTS_FIELD_NUMBER: _ClassVar[int]
    GROUPMETADATA_FIELD_NUMBER: _ClassVar[int]
    GROUPPARTICIPANTS_FIELD_NUMBER: _ClassVar[int]
    REACTIONS_FIELD_NUMBER: _ClassVar[int]
    dataSource: PositronDataSource
    messages: _containers.RepeatedCompositeFieldContainer[PositronMessage]
    chats: _containers.RepeatedCompositeFieldContainer[PositronChat]
    contacts: _containers.RepeatedCompositeFieldContainer[PositronContact]
    groupMetadata: _containers.RepeatedCompositeFieldContainer[PositronGroupMetadata]
    groupParticipants: _containers.RepeatedCompositeFieldContainer[PositronGroupParticipants]
    reactions: _containers.RepeatedCompositeFieldContainer[PositronReaction]
    def __init__(self, dataSource: _Optional[_Union[PositronDataSource, str]] = ..., messages: _Optional[_Iterable[_Union[PositronMessage, _Mapping]]] = ..., chats: _Optional[_Iterable[_Union[PositronChat, _Mapping]]] = ..., contacts: _Optional[_Iterable[_Union[PositronContact, _Mapping]]] = ..., groupMetadata: _Optional[_Iterable[_Union[PositronGroupMetadata, _Mapping]]] = ..., groupParticipants: _Optional[_Iterable[_Union[PositronGroupParticipants, _Mapping]]] = ..., reactions: _Optional[_Iterable[_Union[PositronReaction, _Mapping]]] = ...) -> None: ...
