"""
Call-related event types for PyMeow.

Port of whatsmeow/types/events/call.go
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ...binary.node import Node
from ..jid import JID
from ..call import BasicCallMeta, CallRemoteMeta


@dataclass
class CallOffer(BasicCallMeta, CallRemoteMeta):
    """
    Emitted when the user receives a call on WhatsApp.

    This event contains information about an incoming call, including
    the caller's identity, timestamp, and call metadata.
    """
    data: Optional[Node] = None  # The call offer data


@dataclass
class CallAccept(BasicCallMeta, CallRemoteMeta):
    """
    Emitted when a call is accepted on WhatsApp.

    This event is triggered when either the user or the remote party
    accepts a call, containing information about the accepted call.
    """
    data: Optional[Node] = None


@dataclass
class CallPreAccept(BasicCallMeta, CallRemoteMeta):
    """
    Pre-acceptance state for a call.

    This event is emitted during the call setup process before
    the call is fully accepted.
    """
    data: Optional[Node] = None


@dataclass
class CallTransport(BasicCallMeta, CallRemoteMeta):
    """
    Call transport details.

    This event contains information about the transport layer
    of a call, which is used to establish the media connection.
    """
    data: Optional[Node] = None


@dataclass
class CallOfferNotice(BasicCallMeta):
    """
    Emitted when the user receives a notice of a call on WhatsApp.

    This seems to be primarily for group calls (whereas CallOffer is for 1:1 calls).
    Contains information about the call type and whether it's a group call.
    """
    media: str = ""  # "audio" or "video" depending on call type
    type: str = ""   # "group" when it's a group call

    data: Optional[Node] = None


@dataclass
class CallRelayLatency(BasicCallMeta):
    """
    Emitted slightly after the user receives a call on WhatsApp.

    This event contains information about the latency of the call relay,
    which is used to establish the connection between the caller and callee.
    """
    data: Optional[Node] = None


@dataclass
class CallTerminate(BasicCallMeta):
    """
    Emitted when the other party terminates a call on WhatsApp.

    This event contains information about why the call was terminated,
    including a reason string that explains the termination cause.
    """
    reason: str = ""  # Reason for call termination
    data: Optional[Node] = None


@dataclass
class CallReject(BasicCallMeta):
    """
    Sent when the other party rejects the call on WhatsApp.

    This event is triggered when the remote party explicitly
    rejects an incoming call.
    """
    data: Optional[Node] = None


@dataclass
class UnknownCallEvent:
    """
    Emitted when a call element with unknown content is received.

    This is a fallback event for call-related messages that don't
    match any of the known event types.
    """
    node: Optional[Node] = None
