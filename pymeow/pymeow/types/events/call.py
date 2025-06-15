"""
Call event types for WhatsApp.

Port of whatsmeow/types/events/call.go
"""

from dataclasses import dataclass
from typing import Optional

from ...binary.node import Node
from ..call import BasicCallMeta, CallRemoteMeta
from .events import BaseEvent


@dataclass
class CallOffer(BaseEvent):
    """Emitted when the user receives a call on WhatsApp."""
    basic_call_meta: BasicCallMeta
    call_remote_meta: CallRemoteMeta
    data: Optional[Node] = None


@dataclass
class CallOfferNotice(BaseEvent):
    """Emitted when the user receives a call offer notice."""
    basic_call_meta: BasicCallMeta
    media: str
    type_: str  # Using type_ to avoid conflict with Python keyword
    data: Optional[Node] = None


@dataclass
class CallRelayLatency(BaseEvent):
    """Emitted for call relay latency information."""
    basic_call_meta: BasicCallMeta
    data: Optional[Node] = None


@dataclass
class CallAccept(BaseEvent):
    """Emitted when a call is accepted."""
    basic_call_meta: BasicCallMeta
    call_remote_meta: CallRemoteMeta
    data: Optional[Node] = None


@dataclass
class CallPreAccept(BaseEvent):
    """Emitted when a call is pre-accepted."""
    basic_call_meta: BasicCallMeta
    call_remote_meta: CallRemoteMeta
    data: Optional[Node] = None


@dataclass
class CallTransport(BaseEvent):
    """Emitted for call transport information."""
    basic_call_meta: BasicCallMeta
    call_remote_meta: CallRemoteMeta
    data: Optional[Node] = None


@dataclass
class CallTerminate(BaseEvent):
    """Emitted when a call is terminated."""
    basic_call_meta: BasicCallMeta
    reason: str
    data: Optional[Node] = None


@dataclass
class CallReject(BaseEvent):
    """Emitted when a call is rejected."""
    basic_call_meta: BasicCallMeta
    data: Optional[Node] = None


@dataclass
class UnknownCallEvent(BaseEvent):
    """Emitted when an unknown call event is received."""
    node: Node
