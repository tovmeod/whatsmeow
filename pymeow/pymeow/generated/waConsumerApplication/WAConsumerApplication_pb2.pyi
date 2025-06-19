from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ConsumerApplication(_message.Message):
    __slots__ = ("payload", "metadata")
    class Payload(_message.Message):
        __slots__ = ("content", "applicationData", "signal", "subProtocol")
        CONTENT_FIELD_NUMBER: _ClassVar[int]
        APPLICATIONDATA_FIELD_NUMBER: _ClassVar[int]
        SIGNAL_FIELD_NUMBER: _ClassVar[int]
        SUBPROTOCOL_FIELD_NUMBER: _ClassVar[int]
        content: ConsumerApplication.Content
        applicationData: ConsumerApplication.ApplicationData
        signal: ConsumerApplication.Signal
        subProtocol: ConsumerApplication.SubProtocolPayload
        def __init__(self, content: _Optional[_Union[ConsumerApplication.Content, _Mapping]] = ..., applicationData: _Optional[_Union[ConsumerApplication.ApplicationData, _Mapping]] = ..., signal: _Optional[_Union[ConsumerApplication.Signal, _Mapping]] = ..., subProtocol: _Optional[_Union[ConsumerApplication.SubProtocolPayload, _Mapping]] = ...) -> None: ...
    class SubProtocolPayload(_message.Message):
        __slots__ = ("futureProof",)
        FUTUREPROOF_FIELD_NUMBER: _ClassVar[int]
        futureProof: _WACommon_pb2.FutureProofBehavior
        def __init__(self, futureProof: _Optional[_Union[_WACommon_pb2.FutureProofBehavior, str]] = ...) -> None: ...
    class Metadata(_message.Message):
        __slots__ = ("specialTextSize",)
        class SpecialTextSize(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SMALL: _ClassVar[ConsumerApplication.Metadata.SpecialTextSize]
            MEDIUM: _ClassVar[ConsumerApplication.Metadata.SpecialTextSize]
            LARGE: _ClassVar[ConsumerApplication.Metadata.SpecialTextSize]
        SMALL: ConsumerApplication.Metadata.SpecialTextSize
        MEDIUM: ConsumerApplication.Metadata.SpecialTextSize
        LARGE: ConsumerApplication.Metadata.SpecialTextSize
        SPECIALTEXTSIZE_FIELD_NUMBER: _ClassVar[int]
        specialTextSize: ConsumerApplication.Metadata.SpecialTextSize
        def __init__(self, specialTextSize: _Optional[_Union[ConsumerApplication.Metadata.SpecialTextSize, str]] = ...) -> None: ...
    class Signal(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class ApplicationData(_message.Message):
        __slots__ = ("revoke",)
        REVOKE_FIELD_NUMBER: _ClassVar[int]
        revoke: ConsumerApplication.RevokeMessage
        def __init__(self, revoke: _Optional[_Union[ConsumerApplication.RevokeMessage, _Mapping]] = ...) -> None: ...
    class Content(_message.Message):
        __slots__ = ("messageText", "imageMessage", "contactMessage", "locationMessage", "extendedTextMessage", "statusTextMessage", "documentMessage", "audioMessage", "videoMessage", "contactsArrayMessage", "liveLocationMessage", "stickerMessage", "groupInviteMessage", "viewOnceMessage", "reactionMessage", "pollCreationMessage", "pollUpdateMessage", "editMessage")
        MESSAGETEXT_FIELD_NUMBER: _ClassVar[int]
        IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        CONTACTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        EXTENDEDTEXTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        STATUSTEXTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        DOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        AUDIOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        CONTACTSARRAYMESSAGE_FIELD_NUMBER: _ClassVar[int]
        LIVELOCATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        STICKERMESSAGE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        VIEWONCEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        REACTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        POLLCREATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        POLLUPDATEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        EDITMESSAGE_FIELD_NUMBER: _ClassVar[int]
        messageText: _WACommon_pb2.MessageText
        imageMessage: ConsumerApplication.ImageMessage
        contactMessage: ConsumerApplication.ContactMessage
        locationMessage: ConsumerApplication.LocationMessage
        extendedTextMessage: ConsumerApplication.ExtendedTextMessage
        statusTextMessage: ConsumerApplication.StatusTextMesage
        documentMessage: ConsumerApplication.DocumentMessage
        audioMessage: ConsumerApplication.AudioMessage
        videoMessage: ConsumerApplication.VideoMessage
        contactsArrayMessage: ConsumerApplication.ContactsArrayMessage
        liveLocationMessage: ConsumerApplication.LiveLocationMessage
        stickerMessage: ConsumerApplication.StickerMessage
        groupInviteMessage: ConsumerApplication.GroupInviteMessage
        viewOnceMessage: ConsumerApplication.ViewOnceMessage
        reactionMessage: ConsumerApplication.ReactionMessage
        pollCreationMessage: ConsumerApplication.PollCreationMessage
        pollUpdateMessage: ConsumerApplication.PollUpdateMessage
        editMessage: ConsumerApplication.EditMessage
        def __init__(self, messageText: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., imageMessage: _Optional[_Union[ConsumerApplication.ImageMessage, _Mapping]] = ..., contactMessage: _Optional[_Union[ConsumerApplication.ContactMessage, _Mapping]] = ..., locationMessage: _Optional[_Union[ConsumerApplication.LocationMessage, _Mapping]] = ..., extendedTextMessage: _Optional[_Union[ConsumerApplication.ExtendedTextMessage, _Mapping]] = ..., statusTextMessage: _Optional[_Union[ConsumerApplication.StatusTextMesage, _Mapping]] = ..., documentMessage: _Optional[_Union[ConsumerApplication.DocumentMessage, _Mapping]] = ..., audioMessage: _Optional[_Union[ConsumerApplication.AudioMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[ConsumerApplication.VideoMessage, _Mapping]] = ..., contactsArrayMessage: _Optional[_Union[ConsumerApplication.ContactsArrayMessage, _Mapping]] = ..., liveLocationMessage: _Optional[_Union[ConsumerApplication.LiveLocationMessage, _Mapping]] = ..., stickerMessage: _Optional[_Union[ConsumerApplication.StickerMessage, _Mapping]] = ..., groupInviteMessage: _Optional[_Union[ConsumerApplication.GroupInviteMessage, _Mapping]] = ..., viewOnceMessage: _Optional[_Union[ConsumerApplication.ViewOnceMessage, _Mapping]] = ..., reactionMessage: _Optional[_Union[ConsumerApplication.ReactionMessage, _Mapping]] = ..., pollCreationMessage: _Optional[_Union[ConsumerApplication.PollCreationMessage, _Mapping]] = ..., pollUpdateMessage: _Optional[_Union[ConsumerApplication.PollUpdateMessage, _Mapping]] = ..., editMessage: _Optional[_Union[ConsumerApplication.EditMessage, _Mapping]] = ...) -> None: ...
    class EditMessage(_message.Message):
        __slots__ = ("key", "message", "timestampMS")
        KEY_FIELD_NUMBER: _ClassVar[int]
        MESSAGE_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
        key: _WACommon_pb2.MessageKey
        message: _WACommon_pb2.MessageText
        timestampMS: int
        def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., message: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., timestampMS: _Optional[int] = ...) -> None: ...
    class PollAddOptionMessage(_message.Message):
        __slots__ = ("pollOption",)
        POLLOPTION_FIELD_NUMBER: _ClassVar[int]
        pollOption: _containers.RepeatedCompositeFieldContainer[ConsumerApplication.Option]
        def __init__(self, pollOption: _Optional[_Iterable[_Union[ConsumerApplication.Option, _Mapping]]] = ...) -> None: ...
    class PollVoteMessage(_message.Message):
        __slots__ = ("selectedOptions", "senderTimestampMS")
        SELECTEDOPTIONS_FIELD_NUMBER: _ClassVar[int]
        SENDERTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
        selectedOptions: _containers.RepeatedScalarFieldContainer[bytes]
        senderTimestampMS: int
        def __init__(self, selectedOptions: _Optional[_Iterable[bytes]] = ..., senderTimestampMS: _Optional[int] = ...) -> None: ...
    class PollEncValue(_message.Message):
        __slots__ = ("encPayload", "encIV")
        ENCPAYLOAD_FIELD_NUMBER: _ClassVar[int]
        ENCIV_FIELD_NUMBER: _ClassVar[int]
        encPayload: bytes
        encIV: bytes
        def __init__(self, encPayload: _Optional[bytes] = ..., encIV: _Optional[bytes] = ...) -> None: ...
    class PollUpdateMessage(_message.Message):
        __slots__ = ("pollCreationMessageKey", "vote", "addOption")
        POLLCREATIONMESSAGEKEY_FIELD_NUMBER: _ClassVar[int]
        VOTE_FIELD_NUMBER: _ClassVar[int]
        ADDOPTION_FIELD_NUMBER: _ClassVar[int]
        pollCreationMessageKey: _WACommon_pb2.MessageKey
        vote: ConsumerApplication.PollEncValue
        addOption: ConsumerApplication.PollEncValue
        def __init__(self, pollCreationMessageKey: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., vote: _Optional[_Union[ConsumerApplication.PollEncValue, _Mapping]] = ..., addOption: _Optional[_Union[ConsumerApplication.PollEncValue, _Mapping]] = ...) -> None: ...
    class PollCreationMessage(_message.Message):
        __slots__ = ("encKey", "name", "options", "selectableOptionsCount")
        ENCKEY_FIELD_NUMBER: _ClassVar[int]
        NAME_FIELD_NUMBER: _ClassVar[int]
        OPTIONS_FIELD_NUMBER: _ClassVar[int]
        SELECTABLEOPTIONSCOUNT_FIELD_NUMBER: _ClassVar[int]
        encKey: bytes
        name: str
        options: _containers.RepeatedCompositeFieldContainer[ConsumerApplication.Option]
        selectableOptionsCount: int
        def __init__(self, encKey: _Optional[bytes] = ..., name: _Optional[str] = ..., options: _Optional[_Iterable[_Union[ConsumerApplication.Option, _Mapping]]] = ..., selectableOptionsCount: _Optional[int] = ...) -> None: ...
    class Option(_message.Message):
        __slots__ = ("optionName",)
        OPTIONNAME_FIELD_NUMBER: _ClassVar[int]
        optionName: str
        def __init__(self, optionName: _Optional[str] = ...) -> None: ...
    class ReactionMessage(_message.Message):
        __slots__ = ("key", "text", "groupingKey", "senderTimestampMS", "reactionMetadataDataclassData", "style")
        KEY_FIELD_NUMBER: _ClassVar[int]
        TEXT_FIELD_NUMBER: _ClassVar[int]
        GROUPINGKEY_FIELD_NUMBER: _ClassVar[int]
        SENDERTIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
        REACTIONMETADATADATACLASSDATA_FIELD_NUMBER: _ClassVar[int]
        STYLE_FIELD_NUMBER: _ClassVar[int]
        key: _WACommon_pb2.MessageKey
        text: str
        groupingKey: str
        senderTimestampMS: int
        reactionMetadataDataclassData: str
        style: int
        def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., text: _Optional[str] = ..., groupingKey: _Optional[str] = ..., senderTimestampMS: _Optional[int] = ..., reactionMetadataDataclassData: _Optional[str] = ..., style: _Optional[int] = ...) -> None: ...
    class RevokeMessage(_message.Message):
        __slots__ = ("key",)
        KEY_FIELD_NUMBER: _ClassVar[int]
        key: _WACommon_pb2.MessageKey
        def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...
    class ViewOnceMessage(_message.Message):
        __slots__ = ("imageMessage", "videoMessage")
        IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
        VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
        imageMessage: ConsumerApplication.ImageMessage
        videoMessage: ConsumerApplication.VideoMessage
        def __init__(self, imageMessage: _Optional[_Union[ConsumerApplication.ImageMessage, _Mapping]] = ..., videoMessage: _Optional[_Union[ConsumerApplication.VideoMessage, _Mapping]] = ...) -> None: ...
    class GroupInviteMessage(_message.Message):
        __slots__ = ("groupJID", "inviteCode", "inviteExpiration", "groupName", "JPEGThumbnail", "caption")
        GROUPJID_FIELD_NUMBER: _ClassVar[int]
        INVITECODE_FIELD_NUMBER: _ClassVar[int]
        INVITEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
        GROUPNAME_FIELD_NUMBER: _ClassVar[int]
        JPEGTHUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        groupJID: str
        inviteCode: str
        inviteExpiration: int
        groupName: str
        JPEGThumbnail: bytes
        caption: _WACommon_pb2.MessageText
        def __init__(self, groupJID: _Optional[str] = ..., inviteCode: _Optional[str] = ..., inviteExpiration: _Optional[int] = ..., groupName: _Optional[str] = ..., JPEGThumbnail: _Optional[bytes] = ..., caption: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ...) -> None: ...
    class LiveLocationMessage(_message.Message):
        __slots__ = ("location", "accuracyInMeters", "speedInMps", "degreesClockwiseFromMagneticNorth", "caption", "sequenceNumber", "timeOffset")
        LOCATION_FIELD_NUMBER: _ClassVar[int]
        ACCURACYINMETERS_FIELD_NUMBER: _ClassVar[int]
        SPEEDINMPS_FIELD_NUMBER: _ClassVar[int]
        DEGREESCLOCKWISEFROMMAGNETICNORTH_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        SEQUENCENUMBER_FIELD_NUMBER: _ClassVar[int]
        TIMEOFFSET_FIELD_NUMBER: _ClassVar[int]
        location: ConsumerApplication.Location
        accuracyInMeters: int
        speedInMps: float
        degreesClockwiseFromMagneticNorth: int
        caption: _WACommon_pb2.MessageText
        sequenceNumber: int
        timeOffset: int
        def __init__(self, location: _Optional[_Union[ConsumerApplication.Location, _Mapping]] = ..., accuracyInMeters: _Optional[int] = ..., speedInMps: _Optional[float] = ..., degreesClockwiseFromMagneticNorth: _Optional[int] = ..., caption: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., sequenceNumber: _Optional[int] = ..., timeOffset: _Optional[int] = ...) -> None: ...
    class ContactsArrayMessage(_message.Message):
        __slots__ = ("displayName", "contacts")
        DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
        CONTACTS_FIELD_NUMBER: _ClassVar[int]
        displayName: str
        contacts: _containers.RepeatedCompositeFieldContainer[ConsumerApplication.ContactMessage]
        def __init__(self, displayName: _Optional[str] = ..., contacts: _Optional[_Iterable[_Union[ConsumerApplication.ContactMessage, _Mapping]]] = ...) -> None: ...
    class ContactMessage(_message.Message):
        __slots__ = ("contact",)
        CONTACT_FIELD_NUMBER: _ClassVar[int]
        contact: _WACommon_pb2.SubProtocol
        def __init__(self, contact: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ...) -> None: ...
    class StatusTextMesage(_message.Message):
        __slots__ = ("text", "textArgb", "backgroundArgb", "font")
        class FontType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SANS_SERIF: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
            SERIF: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
            NORICAN_REGULAR: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
            BRYNDAN_WRITE: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
            BEBASNEUE_REGULAR: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
            OSWALD_HEAVY: _ClassVar[ConsumerApplication.StatusTextMesage.FontType]
        SANS_SERIF: ConsumerApplication.StatusTextMesage.FontType
        SERIF: ConsumerApplication.StatusTextMesage.FontType
        NORICAN_REGULAR: ConsumerApplication.StatusTextMesage.FontType
        BRYNDAN_WRITE: ConsumerApplication.StatusTextMesage.FontType
        BEBASNEUE_REGULAR: ConsumerApplication.StatusTextMesage.FontType
        OSWALD_HEAVY: ConsumerApplication.StatusTextMesage.FontType
        TEXT_FIELD_NUMBER: _ClassVar[int]
        TEXTARGB_FIELD_NUMBER: _ClassVar[int]
        BACKGROUNDARGB_FIELD_NUMBER: _ClassVar[int]
        FONT_FIELD_NUMBER: _ClassVar[int]
        text: ConsumerApplication.ExtendedTextMessage
        textArgb: int
        backgroundArgb: int
        font: ConsumerApplication.StatusTextMesage.FontType
        def __init__(self, text: _Optional[_Union[ConsumerApplication.ExtendedTextMessage, _Mapping]] = ..., textArgb: _Optional[int] = ..., backgroundArgb: _Optional[int] = ..., font: _Optional[_Union[ConsumerApplication.StatusTextMesage.FontType, str]] = ...) -> None: ...
    class ExtendedTextMessage(_message.Message):
        __slots__ = ("text", "matchedText", "canonicalURL", "description", "title", "thumbnail", "previewType")
        class PreviewType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NONE: _ClassVar[ConsumerApplication.ExtendedTextMessage.PreviewType]
            VIDEO: _ClassVar[ConsumerApplication.ExtendedTextMessage.PreviewType]
        NONE: ConsumerApplication.ExtendedTextMessage.PreviewType
        VIDEO: ConsumerApplication.ExtendedTextMessage.PreviewType
        TEXT_FIELD_NUMBER: _ClassVar[int]
        MATCHEDTEXT_FIELD_NUMBER: _ClassVar[int]
        CANONICALURL_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        TITLE_FIELD_NUMBER: _ClassVar[int]
        THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        PREVIEWTYPE_FIELD_NUMBER: _ClassVar[int]
        text: _WACommon_pb2.MessageText
        matchedText: str
        canonicalURL: str
        description: str
        title: str
        thumbnail: _WACommon_pb2.SubProtocol
        previewType: ConsumerApplication.ExtendedTextMessage.PreviewType
        def __init__(self, text: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., matchedText: _Optional[str] = ..., canonicalURL: _Optional[str] = ..., description: _Optional[str] = ..., title: _Optional[str] = ..., thumbnail: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., previewType: _Optional[_Union[ConsumerApplication.ExtendedTextMessage.PreviewType, str]] = ...) -> None: ...
    class LocationMessage(_message.Message):
        __slots__ = ("location", "address")
        LOCATION_FIELD_NUMBER: _ClassVar[int]
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        location: ConsumerApplication.Location
        address: str
        def __init__(self, location: _Optional[_Union[ConsumerApplication.Location, _Mapping]] = ..., address: _Optional[str] = ...) -> None: ...
    class StickerMessage(_message.Message):
        __slots__ = ("sticker",)
        STICKER_FIELD_NUMBER: _ClassVar[int]
        sticker: _WACommon_pb2.SubProtocol
        def __init__(self, sticker: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ...) -> None: ...
    class DocumentMessage(_message.Message):
        __slots__ = ("document", "fileName")
        DOCUMENT_FIELD_NUMBER: _ClassVar[int]
        FILENAME_FIELD_NUMBER: _ClassVar[int]
        document: _WACommon_pb2.SubProtocol
        fileName: str
        def __init__(self, document: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., fileName: _Optional[str] = ...) -> None: ...
    class VideoMessage(_message.Message):
        __slots__ = ("video", "caption")
        VIDEO_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        video: _WACommon_pb2.SubProtocol
        caption: _WACommon_pb2.MessageText
        def __init__(self, video: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., caption: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ...) -> None: ...
    class AudioMessage(_message.Message):
        __slots__ = ("audio", "PTT")
        AUDIO_FIELD_NUMBER: _ClassVar[int]
        PTT_FIELD_NUMBER: _ClassVar[int]
        audio: _WACommon_pb2.SubProtocol
        PTT: bool
        def __init__(self, audio: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., PTT: bool = ...) -> None: ...
    class ImageMessage(_message.Message):
        __slots__ = ("image", "caption")
        IMAGE_FIELD_NUMBER: _ClassVar[int]
        CAPTION_FIELD_NUMBER: _ClassVar[int]
        image: _WACommon_pb2.SubProtocol
        caption: _WACommon_pb2.MessageText
        def __init__(self, image: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., caption: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ...) -> None: ...
    class InteractiveAnnotation(_message.Message):
        __slots__ = ("location", "polygonVertices")
        LOCATION_FIELD_NUMBER: _ClassVar[int]
        POLYGONVERTICES_FIELD_NUMBER: _ClassVar[int]
        location: ConsumerApplication.Location
        polygonVertices: _containers.RepeatedCompositeFieldContainer[ConsumerApplication.Point]
        def __init__(self, location: _Optional[_Union[ConsumerApplication.Location, _Mapping]] = ..., polygonVertices: _Optional[_Iterable[_Union[ConsumerApplication.Point, _Mapping]]] = ...) -> None: ...
    class Point(_message.Message):
        __slots__ = ("x", "y")
        X_FIELD_NUMBER: _ClassVar[int]
        Y_FIELD_NUMBER: _ClassVar[int]
        x: float
        y: float
        def __init__(self, x: _Optional[float] = ..., y: _Optional[float] = ...) -> None: ...
    class Location(_message.Message):
        __slots__ = ("degreesLatitude", "degreesLongitude", "name")
        DEGREESLATITUDE_FIELD_NUMBER: _ClassVar[int]
        DEGREESLONGITUDE_FIELD_NUMBER: _ClassVar[int]
        NAME_FIELD_NUMBER: _ClassVar[int]
        degreesLatitude: float
        degreesLongitude: float
        name: str
        def __init__(self, degreesLatitude: _Optional[float] = ..., degreesLongitude: _Optional[float] = ..., name: _Optional[str] = ...) -> None: ...
    class MediaPayload(_message.Message):
        __slots__ = ("protocol",)
        PROTOCOL_FIELD_NUMBER: _ClassVar[int]
        protocol: _WACommon_pb2.SubProtocol
        def __init__(self, protocol: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ...) -> None: ...
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    payload: ConsumerApplication.Payload
    metadata: ConsumerApplication.Metadata
    def __init__(self, payload: _Optional[_Union[ConsumerApplication.Payload, _Mapping]] = ..., metadata: _Optional[_Union[ConsumerApplication.Metadata, _Mapping]] = ...) -> None: ...
