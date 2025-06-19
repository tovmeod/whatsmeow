from waArmadilloXMA import WAArmadilloXMA_pb2 as _WAArmadilloXMA_pb2
from waCommon import WACommon_pb2 as _WACommon_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Armadillo(_message.Message):
    __slots__ = ("payload", "metadata")
    class Metadata(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Payload(_message.Message):
        __slots__ = ("content", "applicationData", "signal", "subProtocol")
        CONTENT_FIELD_NUMBER: _ClassVar[int]
        APPLICATIONDATA_FIELD_NUMBER: _ClassVar[int]
        SIGNAL_FIELD_NUMBER: _ClassVar[int]
        SUBPROTOCOL_FIELD_NUMBER: _ClassVar[int]
        content: Armadillo.Content
        applicationData: Armadillo.ApplicationData
        signal: Armadillo.Signal
        subProtocol: Armadillo.SubProtocolPayload
        def __init__(self, content: _Optional[_Union[Armadillo.Content, _Mapping]] = ..., applicationData: _Optional[_Union[Armadillo.ApplicationData, _Mapping]] = ..., signal: _Optional[_Union[Armadillo.Signal, _Mapping]] = ..., subProtocol: _Optional[_Union[Armadillo.SubProtocolPayload, _Mapping]] = ...) -> None: ...
    class SubProtocolPayload(_message.Message):
        __slots__ = ("futureProof",)
        FUTUREPROOF_FIELD_NUMBER: _ClassVar[int]
        futureProof: _WACommon_pb2.FutureProofBehavior
        def __init__(self, futureProof: _Optional[_Union[_WACommon_pb2.FutureProofBehavior, str]] = ...) -> None: ...
    class Signal(_message.Message):
        __slots__ = ("encryptedBackupsSecrets",)
        class EncryptedBackupsSecrets(_message.Message):
            __slots__ = ("backupID", "serverDataID", "epoch", "tempOcmfClientState", "mailboxRootKey", "obliviousValidationToken")
            class Epoch(_message.Message):
                __slots__ = ("ID", "anonID", "rootKey", "status")
                class EpochStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                    __slots__ = ()
                    ES_OPEN: _ClassVar[Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus]
                    ES_CLOSE: _ClassVar[Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus]
                ES_OPEN: Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus
                ES_CLOSE: Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus
                ID_FIELD_NUMBER: _ClassVar[int]
                ANONID_FIELD_NUMBER: _ClassVar[int]
                ROOTKEY_FIELD_NUMBER: _ClassVar[int]
                STATUS_FIELD_NUMBER: _ClassVar[int]
                ID: int
                anonID: bytes
                rootKey: bytes
                status: Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus
                def __init__(self, ID: _Optional[int] = ..., anonID: _Optional[bytes] = ..., rootKey: _Optional[bytes] = ..., status: _Optional[_Union[Armadillo.Signal.EncryptedBackupsSecrets.Epoch.EpochStatus, str]] = ...) -> None: ...
            BACKUPID_FIELD_NUMBER: _ClassVar[int]
            SERVERDATAID_FIELD_NUMBER: _ClassVar[int]
            EPOCH_FIELD_NUMBER: _ClassVar[int]
            TEMPOCMFCLIENTSTATE_FIELD_NUMBER: _ClassVar[int]
            MAILBOXROOTKEY_FIELD_NUMBER: _ClassVar[int]
            OBLIVIOUSVALIDATIONTOKEN_FIELD_NUMBER: _ClassVar[int]
            backupID: int
            serverDataID: int
            epoch: _containers.RepeatedCompositeFieldContainer[Armadillo.Signal.EncryptedBackupsSecrets.Epoch]
            tempOcmfClientState: bytes
            mailboxRootKey: bytes
            obliviousValidationToken: bytes
            def __init__(self, backupID: _Optional[int] = ..., serverDataID: _Optional[int] = ..., epoch: _Optional[_Iterable[_Union[Armadillo.Signal.EncryptedBackupsSecrets.Epoch, _Mapping]]] = ..., tempOcmfClientState: _Optional[bytes] = ..., mailboxRootKey: _Optional[bytes] = ..., obliviousValidationToken: _Optional[bytes] = ...) -> None: ...
        ENCRYPTEDBACKUPSSECRETS_FIELD_NUMBER: _ClassVar[int]
        encryptedBackupsSecrets: Armadillo.Signal.EncryptedBackupsSecrets
        def __init__(self, encryptedBackupsSecrets: _Optional[_Union[Armadillo.Signal.EncryptedBackupsSecrets, _Mapping]] = ...) -> None: ...
    class ApplicationData(_message.Message):
        __slots__ = ("metadataSync", "aiBotResponse", "messageHistoryDocumentMessage")
        class MessageHistoryDocumentMessage(_message.Message):
            __slots__ = ("document",)
            DOCUMENT_FIELD_NUMBER: _ClassVar[int]
            document: _WACommon_pb2.SubProtocol
            def __init__(self, document: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ...) -> None: ...
        class AIBotResponseMessage(_message.Message):
            __slots__ = ("summonToken", "messageText", "serializedExtras")
            SUMMONTOKEN_FIELD_NUMBER: _ClassVar[int]
            MESSAGETEXT_FIELD_NUMBER: _ClassVar[int]
            SERIALIZEDEXTRAS_FIELD_NUMBER: _ClassVar[int]
            summonToken: str
            messageText: str
            serializedExtras: str
            def __init__(self, summonToken: _Optional[str] = ..., messageText: _Optional[str] = ..., serializedExtras: _Optional[str] = ...) -> None: ...
        class MetadataSyncAction(_message.Message):
            __slots__ = ("chatAction", "messageAction", "actionTimestamp")
            class SyncMessageAction(_message.Message):
                __slots__ = ("messageDelete", "key")
                class ActionMessageDelete(_message.Message):
                    __slots__ = ()
                    def __init__(self) -> None: ...
                MESSAGEDELETE_FIELD_NUMBER: _ClassVar[int]
                KEY_FIELD_NUMBER: _ClassVar[int]
                messageDelete: Armadillo.ApplicationData.MetadataSyncAction.SyncMessageAction.ActionMessageDelete
                key: _WACommon_pb2.MessageKey
                def __init__(self, messageDelete: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncMessageAction.ActionMessageDelete, _Mapping]] = ..., key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...
            class SyncChatAction(_message.Message):
                __slots__ = ("chatArchive", "chatDelete", "chatRead", "chatID")
                class ActionChatRead(_message.Message):
                    __slots__ = ("messageRange", "read")
                    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
                    READ_FIELD_NUMBER: _ClassVar[int]
                    messageRange: Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange
                    read: bool
                    def __init__(self, messageRange: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange, _Mapping]] = ..., read: bool = ...) -> None: ...
                class ActionChatDelete(_message.Message):
                    __slots__ = ("messageRange",)
                    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
                    messageRange: Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange
                    def __init__(self, messageRange: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange, _Mapping]] = ...) -> None: ...
                class ActionChatArchive(_message.Message):
                    __slots__ = ("messageRange", "archived")
                    MESSAGERANGE_FIELD_NUMBER: _ClassVar[int]
                    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
                    messageRange: Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange
                    archived: bool
                    def __init__(self, messageRange: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessageRange, _Mapping]] = ..., archived: bool = ...) -> None: ...
                CHATARCHIVE_FIELD_NUMBER: _ClassVar[int]
                CHATDELETE_FIELD_NUMBER: _ClassVar[int]
                CHATREAD_FIELD_NUMBER: _ClassVar[int]
                CHATID_FIELD_NUMBER: _ClassVar[int]
                chatArchive: Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatArchive
                chatDelete: Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatDelete
                chatRead: Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatRead
                chatID: str
                def __init__(self, chatArchive: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatArchive, _Mapping]] = ..., chatDelete: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatDelete, _Mapping]] = ..., chatRead: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction.ActionChatRead, _Mapping]] = ..., chatID: _Optional[str] = ...) -> None: ...
            class SyncActionMessage(_message.Message):
                __slots__ = ("key", "timestamp")
                KEY_FIELD_NUMBER: _ClassVar[int]
                TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                key: _WACommon_pb2.MessageKey
                timestamp: int
                def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., timestamp: _Optional[int] = ...) -> None: ...
            class SyncActionMessageRange(_message.Message):
                __slots__ = ("lastMessageTimestamp", "lastSystemMessageTimestamp", "messages")
                LASTMESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                LASTSYSTEMMESSAGETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
                MESSAGES_FIELD_NUMBER: _ClassVar[int]
                lastMessageTimestamp: int
                lastSystemMessageTimestamp: int
                messages: _containers.RepeatedCompositeFieldContainer[Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessage]
                def __init__(self, lastMessageTimestamp: _Optional[int] = ..., lastSystemMessageTimestamp: _Optional[int] = ..., messages: _Optional[_Iterable[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncActionMessage, _Mapping]]] = ...) -> None: ...
            CHATACTION_FIELD_NUMBER: _ClassVar[int]
            MESSAGEACTION_FIELD_NUMBER: _ClassVar[int]
            ACTIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            chatAction: Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction
            messageAction: Armadillo.ApplicationData.MetadataSyncAction.SyncMessageAction
            actionTimestamp: int
            def __init__(self, chatAction: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncChatAction, _Mapping]] = ..., messageAction: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncAction.SyncMessageAction, _Mapping]] = ..., actionTimestamp: _Optional[int] = ...) -> None: ...
        class MetadataSyncNotification(_message.Message):
            __slots__ = ("actions",)
            ACTIONS_FIELD_NUMBER: _ClassVar[int]
            actions: _containers.RepeatedCompositeFieldContainer[Armadillo.ApplicationData.MetadataSyncAction]
            def __init__(self, actions: _Optional[_Iterable[_Union[Armadillo.ApplicationData.MetadataSyncAction, _Mapping]]] = ...) -> None: ...
        METADATASYNC_FIELD_NUMBER: _ClassVar[int]
        AIBOTRESPONSE_FIELD_NUMBER: _ClassVar[int]
        MESSAGEHISTORYDOCUMENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        metadataSync: Armadillo.ApplicationData.MetadataSyncNotification
        aiBotResponse: Armadillo.ApplicationData.AIBotResponseMessage
        messageHistoryDocumentMessage: Armadillo.ApplicationData.MessageHistoryDocumentMessage
        def __init__(self, metadataSync: _Optional[_Union[Armadillo.ApplicationData.MetadataSyncNotification, _Mapping]] = ..., aiBotResponse: _Optional[_Union[Armadillo.ApplicationData.AIBotResponseMessage, _Mapping]] = ..., messageHistoryDocumentMessage: _Optional[_Union[Armadillo.ApplicationData.MessageHistoryDocumentMessage, _Mapping]] = ...) -> None: ...
    class Content(_message.Message):
        __slots__ = ("commonSticker", "screenshotAction", "extendedContentMessage", "ravenMessage", "ravenActionNotifMessage", "extendedMessageContentWithSear", "imageGalleryMessage", "paymentsTransactionMessage", "bumpExistingMessage", "noteReplyMessage", "ravenMessageMsgr", "networkVerificationMessage")
        class PaymentsTransactionMessage(_message.Message):
            __slots__ = ("transactionID", "amount", "currency", "paymentStatus", "extendedContentMessage")
            class PaymentStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                PAYMENT_UNKNOWN: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_INITED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_DECLINED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_TRANSFER_INITED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_TRANSFER_COMPLETED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_TRANSFER_FAILED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_CANCELED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                REQUEST_EXPIRED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_INITED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_PENDING: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_PENDING_RECIPIENT_VERIFICATION: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_CANCELED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_COMPLETED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_NO_RECEIVER_CREDENTIAL_NO_RTS_PENDING_CANCELED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_NO_RECEIVER_CREDENTIAL_NO_RTS_PENDING_OTHER: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_REFUNDED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_PARTIAL_REFUND: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_CHARGED_BACK: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_EXPIRED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_DECLINED: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
                TRANSFER_UNAVAILABLE: _ClassVar[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus]
            PAYMENT_UNKNOWN: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_INITED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_DECLINED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_TRANSFER_INITED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_TRANSFER_COMPLETED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_TRANSFER_FAILED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_CANCELED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            REQUEST_EXPIRED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_INITED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_PENDING: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_PENDING_RECIPIENT_VERIFICATION: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_CANCELED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_COMPLETED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_NO_RECEIVER_CREDENTIAL_NO_RTS_PENDING_CANCELED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_NO_RECEIVER_CREDENTIAL_NO_RTS_PENDING_OTHER: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_REFUNDED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_PARTIAL_REFUND: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_CHARGED_BACK: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_EXPIRED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_DECLINED: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSFER_UNAVAILABLE: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            TRANSACTIONID_FIELD_NUMBER: _ClassVar[int]
            AMOUNT_FIELD_NUMBER: _ClassVar[int]
            CURRENCY_FIELD_NUMBER: _ClassVar[int]
            PAYMENTSTATUS_FIELD_NUMBER: _ClassVar[int]
            EXTENDEDCONTENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
            transactionID: int
            amount: str
            currency: str
            paymentStatus: Armadillo.Content.PaymentsTransactionMessage.PaymentStatus
            extendedContentMessage: _WAArmadilloXMA_pb2.ExtendedContentMessage
            def __init__(self, transactionID: _Optional[int] = ..., amount: _Optional[str] = ..., currency: _Optional[str] = ..., paymentStatus: _Optional[_Union[Armadillo.Content.PaymentsTransactionMessage.PaymentStatus, str]] = ..., extendedContentMessage: _Optional[_Union[_WAArmadilloXMA_pb2.ExtendedContentMessage, _Mapping]] = ...) -> None: ...
        class NetworkVerificationMessage(_message.Message):
            __slots__ = ("codeText",)
            CODETEXT_FIELD_NUMBER: _ClassVar[int]
            codeText: str
            def __init__(self, codeText: _Optional[str] = ...) -> None: ...
        class NoteReplyMessage(_message.Message):
            __slots__ = ("textContent", "stickerContent", "videoContent", "noteID", "noteText", "noteTimestampMS")
            TEXTCONTENT_FIELD_NUMBER: _ClassVar[int]
            STICKERCONTENT_FIELD_NUMBER: _ClassVar[int]
            VIDEOCONTENT_FIELD_NUMBER: _ClassVar[int]
            NOTEID_FIELD_NUMBER: _ClassVar[int]
            NOTETEXT_FIELD_NUMBER: _ClassVar[int]
            NOTETIMESTAMPMS_FIELD_NUMBER: _ClassVar[int]
            textContent: _WACommon_pb2.MessageText
            stickerContent: _WACommon_pb2.SubProtocol
            videoContent: _WACommon_pb2.SubProtocol
            noteID: str
            noteText: _WACommon_pb2.MessageText
            noteTimestampMS: int
            def __init__(self, textContent: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., stickerContent: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., videoContent: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., noteID: _Optional[str] = ..., noteText: _Optional[_Union[_WACommon_pb2.MessageText, _Mapping]] = ..., noteTimestampMS: _Optional[int] = ...) -> None: ...
        class BumpExistingMessage(_message.Message):
            __slots__ = ("key",)
            KEY_FIELD_NUMBER: _ClassVar[int]
            key: _WACommon_pb2.MessageKey
            def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ...) -> None: ...
        class ImageGalleryMessage(_message.Message):
            __slots__ = ("images",)
            IMAGES_FIELD_NUMBER: _ClassVar[int]
            images: _containers.RepeatedCompositeFieldContainer[_WACommon_pb2.SubProtocol]
            def __init__(self, images: _Optional[_Iterable[_Union[_WACommon_pb2.SubProtocol, _Mapping]]] = ...) -> None: ...
        class ScreenshotAction(_message.Message):
            __slots__ = ("screenshotType",)
            class ScreenshotType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                SCREENSHOT_IMAGE: _ClassVar[Armadillo.Content.ScreenshotAction.ScreenshotType]
                SCREEN_RECORDING: _ClassVar[Armadillo.Content.ScreenshotAction.ScreenshotType]
            SCREENSHOT_IMAGE: Armadillo.Content.ScreenshotAction.ScreenshotType
            SCREEN_RECORDING: Armadillo.Content.ScreenshotAction.ScreenshotType
            SCREENSHOTTYPE_FIELD_NUMBER: _ClassVar[int]
            screenshotType: Armadillo.Content.ScreenshotAction.ScreenshotType
            def __init__(self, screenshotType: _Optional[_Union[Armadillo.Content.ScreenshotAction.ScreenshotType, str]] = ...) -> None: ...
        class ExtendedContentMessageWithSear(_message.Message):
            __slots__ = ("searID", "payload", "nativeURL", "searAssociatedMessage", "searSentWithMessageID")
            SEARID_FIELD_NUMBER: _ClassVar[int]
            PAYLOAD_FIELD_NUMBER: _ClassVar[int]
            NATIVEURL_FIELD_NUMBER: _ClassVar[int]
            SEARASSOCIATEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
            SEARSENTWITHMESSAGEID_FIELD_NUMBER: _ClassVar[int]
            searID: str
            payload: bytes
            nativeURL: str
            searAssociatedMessage: _WACommon_pb2.SubProtocol
            searSentWithMessageID: str
            def __init__(self, searID: _Optional[str] = ..., payload: _Optional[bytes] = ..., nativeURL: _Optional[str] = ..., searAssociatedMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., searSentWithMessageID: _Optional[str] = ...) -> None: ...
        class RavenActionNotifMessage(_message.Message):
            __slots__ = ("key", "actionTimestamp", "actionType")
            class ActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                PLAYED: _ClassVar[Armadillo.Content.RavenActionNotifMessage.ActionType]
                SCREENSHOT: _ClassVar[Armadillo.Content.RavenActionNotifMessage.ActionType]
                FORCE_DISABLE: _ClassVar[Armadillo.Content.RavenActionNotifMessage.ActionType]
            PLAYED: Armadillo.Content.RavenActionNotifMessage.ActionType
            SCREENSHOT: Armadillo.Content.RavenActionNotifMessage.ActionType
            FORCE_DISABLE: Armadillo.Content.RavenActionNotifMessage.ActionType
            KEY_FIELD_NUMBER: _ClassVar[int]
            ACTIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            ACTIONTYPE_FIELD_NUMBER: _ClassVar[int]
            key: _WACommon_pb2.MessageKey
            actionTimestamp: int
            actionType: Armadillo.Content.RavenActionNotifMessage.ActionType
            def __init__(self, key: _Optional[_Union[_WACommon_pb2.MessageKey, _Mapping]] = ..., actionTimestamp: _Optional[int] = ..., actionType: _Optional[_Union[Armadillo.Content.RavenActionNotifMessage.ActionType, str]] = ...) -> None: ...
        class RavenMessage(_message.Message):
            __slots__ = ("imageMessage", "videoMessage", "ephemeralType")
            class EphemeralType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                VIEW_ONCE: _ClassVar[Armadillo.Content.RavenMessage.EphemeralType]
                ALLOW_REPLAY: _ClassVar[Armadillo.Content.RavenMessage.EphemeralType]
                KEEP_IN_CHAT: _ClassVar[Armadillo.Content.RavenMessage.EphemeralType]
            VIEW_ONCE: Armadillo.Content.RavenMessage.EphemeralType
            ALLOW_REPLAY: Armadillo.Content.RavenMessage.EphemeralType
            KEEP_IN_CHAT: Armadillo.Content.RavenMessage.EphemeralType
            IMAGEMESSAGE_FIELD_NUMBER: _ClassVar[int]
            VIDEOMESSAGE_FIELD_NUMBER: _ClassVar[int]
            EPHEMERALTYPE_FIELD_NUMBER: _ClassVar[int]
            imageMessage: _WACommon_pb2.SubProtocol
            videoMessage: _WACommon_pb2.SubProtocol
            ephemeralType: Armadillo.Content.RavenMessage.EphemeralType
            def __init__(self, imageMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., videoMessage: _Optional[_Union[_WACommon_pb2.SubProtocol, _Mapping]] = ..., ephemeralType: _Optional[_Union[Armadillo.Content.RavenMessage.EphemeralType, str]] = ...) -> None: ...
        class CommonSticker(_message.Message):
            __slots__ = ("stickerType",)
            class StickerType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                SMALL_LIKE: _ClassVar[Armadillo.Content.CommonSticker.StickerType]
                MEDIUM_LIKE: _ClassVar[Armadillo.Content.CommonSticker.StickerType]
                LARGE_LIKE: _ClassVar[Armadillo.Content.CommonSticker.StickerType]
            SMALL_LIKE: Armadillo.Content.CommonSticker.StickerType
            MEDIUM_LIKE: Armadillo.Content.CommonSticker.StickerType
            LARGE_LIKE: Armadillo.Content.CommonSticker.StickerType
            STICKERTYPE_FIELD_NUMBER: _ClassVar[int]
            stickerType: Armadillo.Content.CommonSticker.StickerType
            def __init__(self, stickerType: _Optional[_Union[Armadillo.Content.CommonSticker.StickerType, str]] = ...) -> None: ...
        COMMONSTICKER_FIELD_NUMBER: _ClassVar[int]
        SCREENSHOTACTION_FIELD_NUMBER: _ClassVar[int]
        EXTENDEDCONTENTMESSAGE_FIELD_NUMBER: _ClassVar[int]
        RAVENMESSAGE_FIELD_NUMBER: _ClassVar[int]
        RAVENACTIONNOTIFMESSAGE_FIELD_NUMBER: _ClassVar[int]
        EXTENDEDMESSAGECONTENTWITHSEAR_FIELD_NUMBER: _ClassVar[int]
        IMAGEGALLERYMESSAGE_FIELD_NUMBER: _ClassVar[int]
        PAYMENTSTRANSACTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        BUMPEXISTINGMESSAGE_FIELD_NUMBER: _ClassVar[int]
        NOTEREPLYMESSAGE_FIELD_NUMBER: _ClassVar[int]
        RAVENMESSAGEMSGR_FIELD_NUMBER: _ClassVar[int]
        NETWORKVERIFICATIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
        commonSticker: Armadillo.Content.CommonSticker
        screenshotAction: Armadillo.Content.ScreenshotAction
        extendedContentMessage: _WAArmadilloXMA_pb2.ExtendedContentMessage
        ravenMessage: Armadillo.Content.RavenMessage
        ravenActionNotifMessage: Armadillo.Content.RavenActionNotifMessage
        extendedMessageContentWithSear: Armadillo.Content.ExtendedContentMessageWithSear
        imageGalleryMessage: Armadillo.Content.ImageGalleryMessage
        paymentsTransactionMessage: Armadillo.Content.PaymentsTransactionMessage
        bumpExistingMessage: Armadillo.Content.BumpExistingMessage
        noteReplyMessage: Armadillo.Content.NoteReplyMessage
        ravenMessageMsgr: Armadillo.Content.RavenMessage
        networkVerificationMessage: Armadillo.Content.NetworkVerificationMessage
        def __init__(self, commonSticker: _Optional[_Union[Armadillo.Content.CommonSticker, _Mapping]] = ..., screenshotAction: _Optional[_Union[Armadillo.Content.ScreenshotAction, _Mapping]] = ..., extendedContentMessage: _Optional[_Union[_WAArmadilloXMA_pb2.ExtendedContentMessage, _Mapping]] = ..., ravenMessage: _Optional[_Union[Armadillo.Content.RavenMessage, _Mapping]] = ..., ravenActionNotifMessage: _Optional[_Union[Armadillo.Content.RavenActionNotifMessage, _Mapping]] = ..., extendedMessageContentWithSear: _Optional[_Union[Armadillo.Content.ExtendedContentMessageWithSear, _Mapping]] = ..., imageGalleryMessage: _Optional[_Union[Armadillo.Content.ImageGalleryMessage, _Mapping]] = ..., paymentsTransactionMessage: _Optional[_Union[Armadillo.Content.PaymentsTransactionMessage, _Mapping]] = ..., bumpExistingMessage: _Optional[_Union[Armadillo.Content.BumpExistingMessage, _Mapping]] = ..., noteReplyMessage: _Optional[_Union[Armadillo.Content.NoteReplyMessage, _Mapping]] = ..., ravenMessageMsgr: _Optional[_Union[Armadillo.Content.RavenMessage, _Mapping]] = ..., networkVerificationMessage: _Optional[_Union[Armadillo.Content.NetworkVerificationMessage, _Mapping]] = ...) -> None: ...
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    payload: Armadillo.Payload
    metadata: Armadillo.Metadata
    def __init__(self, payload: _Optional[_Union[Armadillo.Payload, _Mapping]] = ..., metadata: _Optional[_Union[Armadillo.Metadata, _Mapping]] = ...) -> None: ...
