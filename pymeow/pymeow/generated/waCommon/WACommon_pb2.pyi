from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FutureProofBehavior(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PLACEHOLDER: _ClassVar[FutureProofBehavior]
    NO_PLACEHOLDER: _ClassVar[FutureProofBehavior]
    IGNORE: _ClassVar[FutureProofBehavior]
PLACEHOLDER: FutureProofBehavior
NO_PLACEHOLDER: FutureProofBehavior
IGNORE: FutureProofBehavior

class MessageKey(_message.Message):
    __slots__ = ("remoteJID", "fromMe", "ID", "participant")
    REMOTEJID_FIELD_NUMBER: _ClassVar[int]
    FROMME_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_FIELD_NUMBER: _ClassVar[int]
    remoteJID: str
    fromMe: bool
    ID: str
    participant: str
    def __init__(self, remoteJID: _Optional[str] = ..., fromMe: bool = ..., ID: _Optional[str] = ..., participant: _Optional[str] = ...) -> None: ...

class Command(_message.Message):
    __slots__ = ("commandType", "offset", "length", "validationToken")
    class CommandType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        EVERYONE: _ClassVar[Command.CommandType]
        SILENT: _ClassVar[Command.CommandType]
        AI: _ClassVar[Command.CommandType]
        AI_IMAGINE: _ClassVar[Command.CommandType]
    EVERYONE: Command.CommandType
    SILENT: Command.CommandType
    AI: Command.CommandType
    AI_IMAGINE: Command.CommandType
    COMMANDTYPE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    VALIDATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    commandType: Command.CommandType
    offset: int
    length: int
    validationToken: str
    def __init__(self, commandType: _Optional[_Union[Command.CommandType, str]] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ..., validationToken: _Optional[str] = ...) -> None: ...

class Mention(_message.Message):
    __slots__ = ("mentionType", "mentionedJID", "offset", "length")
    class MentionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        PROFILE: _ClassVar[Mention.MentionType]
    PROFILE: Mention.MentionType
    MENTIONTYPE_FIELD_NUMBER: _ClassVar[int]
    MENTIONEDJID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    mentionType: Mention.MentionType
    mentionedJID: str
    offset: int
    length: int
    def __init__(self, mentionType: _Optional[_Union[Mention.MentionType, str]] = ..., mentionedJID: _Optional[str] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class MessageText(_message.Message):
    __slots__ = ("text", "mentionedJID", "commands", "mentions")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    MENTIONEDJID_FIELD_NUMBER: _ClassVar[int]
    COMMANDS_FIELD_NUMBER: _ClassVar[int]
    MENTIONS_FIELD_NUMBER: _ClassVar[int]
    text: str
    mentionedJID: _containers.RepeatedScalarFieldContainer[str]
    commands: _containers.RepeatedCompositeFieldContainer[Command]
    mentions: _containers.RepeatedCompositeFieldContainer[Mention]
    def __init__(self, text: _Optional[str] = ..., mentionedJID: _Optional[_Iterable[str]] = ..., commands: _Optional[_Iterable[_Union[Command, _Mapping]]] = ..., mentions: _Optional[_Iterable[_Union[Mention, _Mapping]]] = ...) -> None: ...

class SubProtocol(_message.Message):
    __slots__ = ("payload", "version")
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    payload: bytes
    version: int
    def __init__(self, payload: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...

class LimitSharing(_message.Message):
    __slots__ = ("sharingLimited", "trigger", "limitSharingSettingTimestamp", "initiatedByMe")
    class Trigger(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[LimitSharing.Trigger]
        CHAT_SETTING: _ClassVar[LimitSharing.Trigger]
        BIZ_SUPPORTS_FB_HOSTING: _ClassVar[LimitSharing.Trigger]
        UNKNOWN_GROUP: _ClassVar[LimitSharing.Trigger]
    UNKNOWN: LimitSharing.Trigger
    CHAT_SETTING: LimitSharing.Trigger
    BIZ_SUPPORTS_FB_HOSTING: LimitSharing.Trigger
    UNKNOWN_GROUP: LimitSharing.Trigger
    SHARINGLIMITED_FIELD_NUMBER: _ClassVar[int]
    TRIGGER_FIELD_NUMBER: _ClassVar[int]
    LIMITSHARINGSETTINGTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    INITIATEDBYME_FIELD_NUMBER: _ClassVar[int]
    sharingLimited: bool
    trigger: LimitSharing.Trigger
    limitSharingSettingTimestamp: int
    initiatedByMe: bool
    def __init__(self, sharingLimited: bool = ..., trigger: _Optional[_Union[LimitSharing.Trigger, str]] = ..., limitSharingSettingTimestamp: _Optional[int] = ..., initiatedByMe: bool = ...) -> None: ...
