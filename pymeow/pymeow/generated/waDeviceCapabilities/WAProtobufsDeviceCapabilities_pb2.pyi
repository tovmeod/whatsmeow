from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DeviceCapabilities(_message.Message):
    __slots__ = ("chatLockSupportLevel", "lidMigration")
    class ChatLockSupportLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[DeviceCapabilities.ChatLockSupportLevel]
        MINIMAL: _ClassVar[DeviceCapabilities.ChatLockSupportLevel]
        FULL: _ClassVar[DeviceCapabilities.ChatLockSupportLevel]
    NONE: DeviceCapabilities.ChatLockSupportLevel
    MINIMAL: DeviceCapabilities.ChatLockSupportLevel
    FULL: DeviceCapabilities.ChatLockSupportLevel
    class LIDMigration(_message.Message):
        __slots__ = ("chatDbMigrationTimestamp",)
        CHATDBMIGRATIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        chatDbMigrationTimestamp: int
        def __init__(self, chatDbMigrationTimestamp: _Optional[int] = ...) -> None: ...
    CHATLOCKSUPPORTLEVEL_FIELD_NUMBER: _ClassVar[int]
    LIDMIGRATION_FIELD_NUMBER: _ClassVar[int]
    chatLockSupportLevel: DeviceCapabilities.ChatLockSupportLevel
    lidMigration: DeviceCapabilities.LIDMigration
    def __init__(self, chatLockSupportLevel: _Optional[_Union[DeviceCapabilities.ChatLockSupportLevel, str]] = ..., lidMigration: _Optional[_Union[DeviceCapabilities.LIDMigration, _Mapping]] = ...) -> None: ...
