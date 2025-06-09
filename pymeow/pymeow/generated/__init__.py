"""Generated protocol buffer classes for WhatsApp Web API.

This package contains all the generated protocol buffer classes from the WhatsApp .proto files.
Classes are organized in submodules matching the original proto package structure.

Example:
    from pymeow.generated.waE2E.WAWebProtobufsE2E_pb2 import StickerPackMessage
    from pymeow.generated.waMsgTransport import WAMsgTransport_pb2
"""

# Import the modules to make them available when importing from the package
from . import waMsgTransport
from .waMsgTransport import WAMsgTransport_pb2
from .waCommon import WACommon_pb2

# Re-export commonly used types
from .waMsgTransport.WAMsgTransport_pb2 import MessageTransport

# For backward compatibility
Message = MessageTransport

__all__ = [
    'Message',  # Backward compatibility alias
    'MessageTransport',
    'WACommon_pb2',
    'WAMsgTransport_pb2',
    'waMsgTransport',
]
