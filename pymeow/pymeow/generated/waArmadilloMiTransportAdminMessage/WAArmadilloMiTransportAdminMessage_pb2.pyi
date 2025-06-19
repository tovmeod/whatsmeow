from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MiTransportAdminMessage(_message.Message):
    __slots__ = ("chatThemeChanged", "nicknameChanged", "groupParticipantChanged", "groupAdminChanged", "groupNameChanged", "groupMembershipAddModeChanged", "messagePinned", "groupImageChanged", "quickReactionChanged", "linkCta", "iconChanged", "disappearingSettingChanged")
    class GroupImageChanged(_message.Message):
        __slots__ = ("action",)
        class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            CHANGED: _ClassVar[MiTransportAdminMessage.GroupImageChanged.Action]
            REMOVED: _ClassVar[MiTransportAdminMessage.GroupImageChanged.Action]
        CHANGED: MiTransportAdminMessage.GroupImageChanged.Action
        REMOVED: MiTransportAdminMessage.GroupImageChanged.Action
        ACTION_FIELD_NUMBER: _ClassVar[int]
        action: MiTransportAdminMessage.GroupImageChanged.Action
        def __init__(self, action: _Optional[_Union[MiTransportAdminMessage.GroupImageChanged.Action, str]] = ...) -> None: ...
    class MessagePinned(_message.Message):
        __slots__ = ("action",)
        class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            PINNED: _ClassVar[MiTransportAdminMessage.MessagePinned.Action]
            UNPINNED: _ClassVar[MiTransportAdminMessage.MessagePinned.Action]
        PINNED: MiTransportAdminMessage.MessagePinned.Action
        UNPINNED: MiTransportAdminMessage.MessagePinned.Action
        ACTION_FIELD_NUMBER: _ClassVar[int]
        action: MiTransportAdminMessage.MessagePinned.Action
        def __init__(self, action: _Optional[_Union[MiTransportAdminMessage.MessagePinned.Action, str]] = ...) -> None: ...
    class GroupMembershipAddModeChanged(_message.Message):
        __slots__ = ("mode",)
        class Mode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            ALL_MEMBERS: _ClassVar[MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode]
            ADMINS_ONLY: _ClassVar[MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode]
        ALL_MEMBERS: MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode
        ADMINS_ONLY: MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode
        MODE_FIELD_NUMBER: _ClassVar[int]
        mode: MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode
        def __init__(self, mode: _Optional[_Union[MiTransportAdminMessage.GroupMembershipAddModeChanged.Mode, str]] = ...) -> None: ...
    class GroupAdminChanged(_message.Message):
        __slots__ = ("targetUserID", "action")
        class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            ADDED: _ClassVar[MiTransportAdminMessage.GroupAdminChanged.Action]
            REMOVED: _ClassVar[MiTransportAdminMessage.GroupAdminChanged.Action]
        ADDED: MiTransportAdminMessage.GroupAdminChanged.Action
        REMOVED: MiTransportAdminMessage.GroupAdminChanged.Action
        TARGETUSERID_FIELD_NUMBER: _ClassVar[int]
        ACTION_FIELD_NUMBER: _ClassVar[int]
        targetUserID: _containers.RepeatedScalarFieldContainer[str]
        action: MiTransportAdminMessage.GroupAdminChanged.Action
        def __init__(self, targetUserID: _Optional[_Iterable[str]] = ..., action: _Optional[_Union[MiTransportAdminMessage.GroupAdminChanged.Action, str]] = ...) -> None: ...
    class GroupParticipantChanged(_message.Message):
        __slots__ = ("targetUserID", "action")
        class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            ADDED: _ClassVar[MiTransportAdminMessage.GroupParticipantChanged.Action]
            REMOVED: _ClassVar[MiTransportAdminMessage.GroupParticipantChanged.Action]
        ADDED: MiTransportAdminMessage.GroupParticipantChanged.Action
        REMOVED: MiTransportAdminMessage.GroupParticipantChanged.Action
        TARGETUSERID_FIELD_NUMBER: _ClassVar[int]
        ACTION_FIELD_NUMBER: _ClassVar[int]
        targetUserID: _containers.RepeatedScalarFieldContainer[str]
        action: MiTransportAdminMessage.GroupParticipantChanged.Action
        def __init__(self, targetUserID: _Optional[_Iterable[str]] = ..., action: _Optional[_Union[MiTransportAdminMessage.GroupParticipantChanged.Action, str]] = ...) -> None: ...
    class DisappearingSettingChanged(_message.Message):
        __slots__ = ("disappearingSettingDurationSeconds", "oldDisappearingSettingDurationSeconds")
        DISAPPEARINGSETTINGDURATIONSECONDS_FIELD_NUMBER: _ClassVar[int]
        OLDDISAPPEARINGSETTINGDURATIONSECONDS_FIELD_NUMBER: _ClassVar[int]
        disappearingSettingDurationSeconds: int
        oldDisappearingSettingDurationSeconds: int
        def __init__(self, disappearingSettingDurationSeconds: _Optional[int] = ..., oldDisappearingSettingDurationSeconds: _Optional[int] = ...) -> None: ...
    class IconChanged(_message.Message):
        __slots__ = ("threadIcon",)
        THREADICON_FIELD_NUMBER: _ClassVar[int]
        threadIcon: str
        def __init__(self, threadIcon: _Optional[str] = ...) -> None: ...
    class LinkCta(_message.Message):
        __slots__ = ("ukOsaAdminText",)
        class UkOsaAdminText(_message.Message):
            __slots__ = ("initiatorUserID",)
            INITIATORUSERID_FIELD_NUMBER: _ClassVar[int]
            initiatorUserID: str
            def __init__(self, initiatorUserID: _Optional[str] = ...) -> None: ...
        UKOSAADMINTEXT_FIELD_NUMBER: _ClassVar[int]
        ukOsaAdminText: MiTransportAdminMessage.LinkCta.UkOsaAdminText
        def __init__(self, ukOsaAdminText: _Optional[_Union[MiTransportAdminMessage.LinkCta.UkOsaAdminText, _Mapping]] = ...) -> None: ...
    class QuickReactionChanged(_message.Message):
        __slots__ = ("emojiName",)
        EMOJINAME_FIELD_NUMBER: _ClassVar[int]
        emojiName: str
        def __init__(self, emojiName: _Optional[str] = ...) -> None: ...
    class GroupNameChanged(_message.Message):
        __slots__ = ("groupName",)
        GROUPNAME_FIELD_NUMBER: _ClassVar[int]
        groupName: str
        def __init__(self, groupName: _Optional[str] = ...) -> None: ...
    class NicknameChanged(_message.Message):
        __slots__ = ("targetUserID", "nickname")
        TARGETUSERID_FIELD_NUMBER: _ClassVar[int]
        NICKNAME_FIELD_NUMBER: _ClassVar[int]
        targetUserID: str
        nickname: str
        def __init__(self, targetUserID: _Optional[str] = ..., nickname: _Optional[str] = ...) -> None: ...
    class ChatThemeChanged(_message.Message):
        __slots__ = ("themeName", "themeEmoji", "themeType")
        THEMENAME_FIELD_NUMBER: _ClassVar[int]
        THEMEEMOJI_FIELD_NUMBER: _ClassVar[int]
        THEMETYPE_FIELD_NUMBER: _ClassVar[int]
        themeName: str
        themeEmoji: str
        themeType: int
        def __init__(self, themeName: _Optional[str] = ..., themeEmoji: _Optional[str] = ..., themeType: _Optional[int] = ...) -> None: ...
    CHATTHEMECHANGED_FIELD_NUMBER: _ClassVar[int]
    NICKNAMECHANGED_FIELD_NUMBER: _ClassVar[int]
    GROUPPARTICIPANTCHANGED_FIELD_NUMBER: _ClassVar[int]
    GROUPADMINCHANGED_FIELD_NUMBER: _ClassVar[int]
    GROUPNAMECHANGED_FIELD_NUMBER: _ClassVar[int]
    GROUPMEMBERSHIPADDMODECHANGED_FIELD_NUMBER: _ClassVar[int]
    MESSAGEPINNED_FIELD_NUMBER: _ClassVar[int]
    GROUPIMAGECHANGED_FIELD_NUMBER: _ClassVar[int]
    QUICKREACTIONCHANGED_FIELD_NUMBER: _ClassVar[int]
    LINKCTA_FIELD_NUMBER: _ClassVar[int]
    ICONCHANGED_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGSETTINGCHANGED_FIELD_NUMBER: _ClassVar[int]
    chatThemeChanged: MiTransportAdminMessage.ChatThemeChanged
    nicknameChanged: MiTransportAdminMessage.NicknameChanged
    groupParticipantChanged: MiTransportAdminMessage.GroupParticipantChanged
    groupAdminChanged: MiTransportAdminMessage.GroupAdminChanged
    groupNameChanged: MiTransportAdminMessage.GroupNameChanged
    groupMembershipAddModeChanged: MiTransportAdminMessage.GroupMembershipAddModeChanged
    messagePinned: MiTransportAdminMessage.MessagePinned
    groupImageChanged: MiTransportAdminMessage.GroupImageChanged
    quickReactionChanged: MiTransportAdminMessage.QuickReactionChanged
    linkCta: MiTransportAdminMessage.LinkCta
    iconChanged: MiTransportAdminMessage.IconChanged
    disappearingSettingChanged: MiTransportAdminMessage.DisappearingSettingChanged
    def __init__(self, chatThemeChanged: _Optional[_Union[MiTransportAdminMessage.ChatThemeChanged, _Mapping]] = ..., nicknameChanged: _Optional[_Union[MiTransportAdminMessage.NicknameChanged, _Mapping]] = ..., groupParticipantChanged: _Optional[_Union[MiTransportAdminMessage.GroupParticipantChanged, _Mapping]] = ..., groupAdminChanged: _Optional[_Union[MiTransportAdminMessage.GroupAdminChanged, _Mapping]] = ..., groupNameChanged: _Optional[_Union[MiTransportAdminMessage.GroupNameChanged, _Mapping]] = ..., groupMembershipAddModeChanged: _Optional[_Union[MiTransportAdminMessage.GroupMembershipAddModeChanged, _Mapping]] = ..., messagePinned: _Optional[_Union[MiTransportAdminMessage.MessagePinned, _Mapping]] = ..., groupImageChanged: _Optional[_Union[MiTransportAdminMessage.GroupImageChanged, _Mapping]] = ..., quickReactionChanged: _Optional[_Union[MiTransportAdminMessage.QuickReactionChanged, _Mapping]] = ..., linkCta: _Optional[_Union[MiTransportAdminMessage.LinkCta, _Mapping]] = ..., iconChanged: _Optional[_Union[MiTransportAdminMessage.IconChanged, _Mapping]] = ..., disappearingSettingChanged: _Optional[_Union[MiTransportAdminMessage.DisappearingSettingChanged, _Mapping]] = ...) -> None: ...
