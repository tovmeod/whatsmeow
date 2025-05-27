"""
Node handling for WhatsApp binary protocol.

Port of whatsmeow/binary/node.go
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional, Union

from ..generated.waCommon import WACommon_pb2
from ..generated.waMsgTransport import WAMsgTransport_pb2

@dataclass
class Node:
    """Binary protocol node representation."""
    tag: str
    attributes: Dict[str, str]
    content: Optional[Union[bytes, WACommon_pb2.SubProtocol]] = None
