from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TransportEvent(_message.Message):
    __slots__ = ("placeholder", "event")
    class Event(_message.Message):
        __slots__ = ("deviceChange", "icdcAlert")
        class IcdcAlert(_message.Message):
            __slots__ = ("type",)
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                NONE: _ClassVar[TransportEvent.Event.IcdcAlert.Type]
                DETECTED: _ClassVar[TransportEvent.Event.IcdcAlert.Type]
                CLEARED: _ClassVar[TransportEvent.Event.IcdcAlert.Type]
            NONE: TransportEvent.Event.IcdcAlert.Type
            DETECTED: TransportEvent.Event.IcdcAlert.Type
            CLEARED: TransportEvent.Event.IcdcAlert.Type
            TYPE_FIELD_NUMBER: _ClassVar[int]
            type: TransportEvent.Event.IcdcAlert.Type
            def __init__(self, type: _Optional[_Union[TransportEvent.Event.IcdcAlert.Type, str]] = ...) -> None: ...
        class DeviceChange(_message.Message):
            __slots__ = ("type", "deviceName", "devicePlatform", "deviceModel")
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                NONE: _ClassVar[TransportEvent.Event.DeviceChange.Type]
                ADDED: _ClassVar[TransportEvent.Event.DeviceChange.Type]
                REMOVED: _ClassVar[TransportEvent.Event.DeviceChange.Type]
                REPLACED: _ClassVar[TransportEvent.Event.DeviceChange.Type]
            NONE: TransportEvent.Event.DeviceChange.Type
            ADDED: TransportEvent.Event.DeviceChange.Type
            REMOVED: TransportEvent.Event.DeviceChange.Type
            REPLACED: TransportEvent.Event.DeviceChange.Type
            TYPE_FIELD_NUMBER: _ClassVar[int]
            DEVICENAME_FIELD_NUMBER: _ClassVar[int]
            DEVICEPLATFORM_FIELD_NUMBER: _ClassVar[int]
            DEVICEMODEL_FIELD_NUMBER: _ClassVar[int]
            type: TransportEvent.Event.DeviceChange.Type
            deviceName: str
            devicePlatform: str
            deviceModel: str
            def __init__(self, type: _Optional[_Union[TransportEvent.Event.DeviceChange.Type, str]] = ..., deviceName: _Optional[str] = ..., devicePlatform: _Optional[str] = ..., deviceModel: _Optional[str] = ...) -> None: ...
        DEVICECHANGE_FIELD_NUMBER: _ClassVar[int]
        ICDCALERT_FIELD_NUMBER: _ClassVar[int]
        deviceChange: TransportEvent.Event.DeviceChange
        icdcAlert: TransportEvent.Event.IcdcAlert
        def __init__(self, deviceChange: _Optional[_Union[TransportEvent.Event.DeviceChange, _Mapping]] = ..., icdcAlert: _Optional[_Union[TransportEvent.Event.IcdcAlert, _Mapping]] = ...) -> None: ...
    class Placeholder(_message.Message):
        __slots__ = ("type",)
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DECRYPTION_FAILURE: _ClassVar[TransportEvent.Placeholder.Type]
            UNAVAILABLE_MESSAGE: _ClassVar[TransportEvent.Placeholder.Type]
        DECRYPTION_FAILURE: TransportEvent.Placeholder.Type
        UNAVAILABLE_MESSAGE: TransportEvent.Placeholder.Type
        TYPE_FIELD_NUMBER: _ClassVar[int]
        type: TransportEvent.Placeholder.Type
        def __init__(self, type: _Optional[_Union[TransportEvent.Placeholder.Type, str]] = ...) -> None: ...
    PLACEHOLDER_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    placeholder: TransportEvent.Placeholder
    event: TransportEvent.Event
    def __init__(self, placeholder: _Optional[_Union[TransportEvent.Placeholder, _Mapping]] = ..., event: _Optional[_Union[TransportEvent.Event, _Mapping]] = ...) -> None: ...
