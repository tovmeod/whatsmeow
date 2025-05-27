"""
Call-related event types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Union, Any

from .jid import JID

class CallMediaType(str, Enum):
    """Types of media used in calls."""
    AUDIO = "audio"
    VIDEO = "video"

class CallType(str, Enum):
    """Types of calls."""
    AUDIO = "audio"
    VIDEO = "video"
    GROUP = "group"

class CallState(str, Enum):
    """Possible states of a call."""
    OFFER = "offer"
    RINGING = "ringing"
    TIMEOUT = "timeout"
    REJECT = "reject"
    ACCEPT = "accept"
    OFFERED = "offered"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ENDED = "ended"

@dataclass
class CallParticipant:
    """Information about a call participant."""
    jid: JID
    state: CallState
    is_video_enabled: bool = False
    is_muted: bool = False
    is_screen_sharing: bool = False
    join_time: Optional[datetime] = None
    leave_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'jid': str(self.jid),
            'state': self.state.value,
            'is_video_enabled': self.is_video_enabled,
            'is_muted': self.is_muted,
            'is_screen_sharing': self.is_screen_sharing,
            'join_time': self.join_time.isoformat() if self.join_time else None,
            'leave_time': self.leave_time.isoformat() if self.leave_time else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CallParticipant':
        """Create from dictionary."""
        from datetime import datetime
        return cls(
            jid=JID.from_string(data['jid']),
            state=CallState(data['state']),
            is_video_enabled=data.get('is_video_enabled', False),
            is_muted=data.get('is_muted', False),
            is_screen_sharing=data.get('is_screen_sharing', False),
            join_time=datetime.fromisoformat(data['join_time']) if data.get('join_time') else None,
            leave_time=datetime.fromisoformat(data['leave_time']) if data.get('leave_time') else None,
        )

@dataclass
class CallInfo:
    """Complete information about a call."""
    call_id: str
    from_jid: JID
    to_jid: JID
    call_type: CallType
    state: CallState
    timestamp: datetime
    is_video: bool = False
    is_group: bool = False
    participants: List[CallParticipant] = field(default_factory=list)
    duration: Optional[int] = None  # in seconds
    end_reason: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'call_id': self.call_id,
            'from_jid': str(self.from_jid),
            'to_jid': str(self.to_jid),
            'call_type': self.call_type.value,
            'state': self.state.value,
            'timestamp': self.timestamp.isoformat(),
            'is_video': self.is_video,
            'is_group': self.is_group,
            'participants': [p.to_dict() for p in self.participants],
            'duration': self.duration,
            'end_reason': self.end_reason,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CallInfo':
        """Create from dictionary."""
        from datetime import datetime
        return cls(
            call_id=data['call_id'],
            from_jid=JID.from_string(data['from_jid']),
            to_jid=JID.from_string(data['to_jid']),
            call_type=CallType(data['call_type']),
            state=CallState(data['state']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            is_video=data.get('is_video', False),
            is_group=data.get('is_group', False),
            participants=[CallParticipant.from_dict(p) for p in data.get('participants', [])],
            duration=data.get('duration'),
            end_reason=data.get('end_reason'),
            raw_data=data.get('raw_data'),
        )

@dataclass
class CallOfferEvent:
    """Event for an incoming call offer."""
    call_id: str
    caller_jid: JID
    call_type: CallType
    timestamp: datetime
    offer: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'call_id': self.call_id,
            'caller_jid': str(self.caller_jid),
            'call_type': self.call_type.value,
            'timestamp': self.timestamp.isoformat(),
            'offer': self.offer,
        }

@dataclass
class CallRejectEvent:
    """Event for a rejected call."""
    call_id: str
    from_jid: JID
    timestamp: datetime
    reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'call_id': self.call_id,
            'from_jid': str(self.from_jid),
            'timestamp': self.timestamp.isoformat(),
            'reason': self.reason,
        }

@dataclass
class CallTerminateEvent:
    """Event for a terminated call."""
    call_id: str
    timestamp: datetime
    reason: str
    duration: Optional[int] = None  # in seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'call_id': self.call_id,
            'timestamp': self.timestamp.isoformat(),
            'reason': self.reason,
            'duration': self.duration,
        }
