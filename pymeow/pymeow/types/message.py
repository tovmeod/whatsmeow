"""
Message-related types for PyMeow.
"""
from enum import Enum

# Import generated protobuf classes
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
from pymeow.pymeow.generated_protos.waCommon import WACommon_pb2

# Keep existing enums as per instruction
class MessageType(Enum):
    """Types of messages."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    STICKER = "sticker"
    LOCATION = "location"
    CONTACT = "contact"
    CONTACTS = "contacts"
    GROUP_INVITE = "group_invite"
    LIST = "list"
    BUTTONS = "buttons"
    TEMPLATE = "template"
    REACTION = "reaction"
    POLL_CREATE = "poll_creation"
    POLL_VOTE = "poll_vote"
    UNKNOWN = "unknown"


class MessageStatus(Enum):
    """Status of a message."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    RETRYING = "retrying"

# Assign Protobuf classes to the names previously used by dataclasses
# Message: The main container for different message types
Message = WAWebProtobufsE2E_pb2.Message

# MessageKey: Using the one from waCommon as it seems to be the base definition
# and is used in WAWebProtobufsE2E_pb2.ProtocolMessage.key
MessageKey = WACommon_pb2.MessageKey

# MessageInfo: WAWebProtobufsE2E_pb2.ContextInfo seems the most appropriate replacement
# for the old MessageInfo dataclass's role of holding metadata *about* a message.
# The fields won't map 1:1, and client code will need to adapt.
MessageInfo = WAWebProtobufsE2E_pb2.ContextInfo

# Note: ExpirationInfo and ExpirationType are in .expiration module and should remain there.
# JID is in .jid module and should remain there.
# The refactoring of client logic to use these new Protobuf-based types
# (e.g., accessing fields, handling MessageType mapping) will be done in a subsequent step.
