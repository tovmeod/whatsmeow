"""
Message expiration types for PyMeow.

This module defines types and constants related to disappearing messages.
"""
from enum import Enum, auto
from datetime import datetime, timedelta
from typing import Optional, Union, Dict, Any

class ExpirationType(Enum):
    """Types of message expiration."""
    OFF = 0
    ONE_DAY = 86400         # 24 hours
    ONE_WEEK = 604800       # 7 days
    NINETY_DAYS = 7776000   # 90 days
    ONE_YEAR = 31536000     # 1 year (kept for backward compatibility)
    CUSTOM = -1

    @classmethod
    def _missing_(cls, value):
        # Convert string values to enum members
        if isinstance(value, str):
            value = value.upper().replace(' ', '_')
            for member in cls:
                if member.name == value:
                    return member
        return None

class ExpirationInfo:
    """
    Contains information about a message's expiration settings.
    
    Attributes:
        enabled: Whether disappearing messages are enabled
        duration_seconds: Duration in seconds before message expires
        expiration_timestamp: When the message will expire (if set)
        type: The type of expiration (from ExpirationType enum)
    """
    def __init__(
        self,
        enabled: bool = False,
        duration_seconds: int = 0,
        expiration_timestamp: Optional[Union[int, datetime]] = None,
        expiration_type: Union[ExpirationType, str, None] = None
    ):
        self.enabled = enabled
        self.duration_seconds = duration_seconds
        self.type = self._determine_expiration_type(expiration_type, duration_seconds)
        
        if expiration_timestamp is not None:
            if isinstance(expiration_timestamp, int):
                self.expiration_timestamp = datetime.fromtimestamp(expiration_timestamp)
            else:
                self.expiration_timestamp = expiration_timestamp
        else:
            self.expiration_timestamp = datetime.utcnow() + timedelta(seconds=duration_seconds) if enabled else None
    
    def _determine_expiration_type(self, expiration_type, duration_seconds):
        if expiration_type is not None:
            if isinstance(expiration_type, str):
                return ExpirationType[expiration_type.upper().replace(' ', '_')]
            return expiration_type
        
        if not self.enabled:
            return ExpirationType.OFF
            
        for exp_type in ExpirationType:
            if exp_type.value == duration_seconds and exp_type != ExpirationType.CUSTOM:
                return exp_type
                
        return ExpirationType.CUSTOM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the expiration info to a dictionary."""
        return {
            'enabled': self.enabled,
            'duration_seconds': self.duration_seconds,
            'expiration_timestamp': int(self.expiration_timestamp.timestamp()) if self.expiration_timestamp else None,
            'type': self.type.name if self.type else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExpirationInfo':
        """Create an ExpirationInfo from a dictionary."""
        return cls(
            enabled=data.get('enabled', False),
            duration_seconds=data.get('duration_seconds', 0),
            expiration_timestamp=data.get('expiration_timestamp'),
            expiration_type=data.get('type')
        )
    
    def __repr__(self) -> str:
        if not self.enabled:
            return "ExpirationInfo(disabled)"
        return f"ExpirationInfo(type={self.type.name}, expires_at={self.expiration_timestamp.isoformat()})"
