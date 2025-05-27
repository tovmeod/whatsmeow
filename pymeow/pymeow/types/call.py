"""
Call-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union

from .jid import JID

class CallType(str, Enum):
    """Types of calls."""
    AUDIO = "audio"
    VIDEO = "video"
    SCREEN_SHARE = "screen_share"

class CallState(str, Enum):
    """Possible states of a call."""
    OFFER = "offer"
    RINGING = "ringing"
    TIMEOUT = "timeout"
    REJECT = "reject"
    ACCEPT = "accept"
    TERMINATE = "terminate"
    OFFER_NOTICE = "offer_notice"
    PRE_ACCEPT = "pre_accept"
    TRANSPORT = "transport"

@dataclass
class CallParticipant:
    """Represents a participant in a call."""
    jid: JID
    is_self: bool = False
    is_video_enabled: bool = False
    is_audio_enabled: bool = True
    is_muted: bool = False
    is_hand_raised: bool = False
    is_screen_sharing: bool = False
    join_time: Optional[datetime] = None
    join_timestamp: Optional[int] = None

@dataclass
class CallInfo:
    """Contains information about a call."""
    call_id: str
    call_creator: JID
    call_type: CallType
    call_state: CallState
    from_jid: JID
    to_jid: JID
    timestamp: datetime
    is_video: bool = False
    is_group: bool = False
    is_offer: bool = False
    is_ringing: bool = False
    is_on_hold: bool = False
    is_ended: bool = False
    duration: int = 0  # in seconds
    participants: List[CallParticipant] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.call_creator, str):
            self.call_creator = JID.from_string(self.call_creator)
        if isinstance(self.from_jid, str):
            self.from_jid = JID.from_string(self.from_jid)
        if isinstance(self.to_jid, str):
            self.to_jid = JID.from_string(self.to_jid)
    
    @property
    def is_incoming(self) -> bool:
        """Whether this is an incoming call."""
        return not self.is_outgoing
    
    @property
    def is_outgoing(self) -> bool:
        """Whether this is an outgoing call."""
        return self.call_creator == self.from_jid
    
    def get_participant(self, jid: Union[JID, str]) -> Optional[CallParticipant]:
        """Get a participant by JID."""
        if isinstance(jid, str):
            jid = JID.from_string(jid)
        for participant in self.participants:
            if participant.jid == jid:
                return participant
        return None
    
    def add_participant(self, participant: CallParticipant) -> None:
        """Add a participant to the call."""
        if not any(p.jid == participant.jid for p in self.participants):
            self.participants.append(participant)
    
    def remove_participant(self, jid: Union[JID, str]) -> bool:
        """Remove a participant from the call."""
        if isinstance(jid, str):
            jid = JID.from_string(jid)
        for i, participant in enumerate(self.participants):
            if participant.jid == jid:
                self.participants.pop(i)
                return True
        return False
