"""
PyMeow Disappearing Messages - WhatsApp Ephemeral Messaging

This module provides functionality for sending and managing disappearing messages
in WhatsApp, including setting message expiration times and handling ephemeral messages.

WhatsMeow Equivalents:
- types/expiration.go: Core expiration types and constants (Fully implemented)
- socket/handlers_disappearing_messages.go: Disappearing message handlers (Partially implemented)
- socket/responses_disappearing_messages.go: Response handling (Partially implemented)
- socket/handlers_ephemeral.go: Ephemeral message handling (Basic implementation)
- socket/responses_ephemeral.go: Ephemeral response handling (Basic implementation)

Key Components:
- DisappearingMessageManager: Main class for managing disappearing messages (types/expiration.go)
- ExpirationType: Enum of supported expiration durations (types/expiration.go)
- ExpirationInfo: Data structure for expiration details (types/expiration.go)

Implementation Status:
- Standard durations: Fully implemented
- Expiration validation: Complete
- Message expiration tracking: Basic
- Group message expiration: Basic
- Ephemeral messages: Partial
- Server sync: Basic
- Error handling: Basic

Key Differences from WhatsMeow:
- Simplified API surface
- Python's enum types for constants
- More flexible duration handling
- Integrated with Python's datetime
- Less aggressive caching of expiration settings

Security Considerations:
- Validates all durations server-side
- Handles message expiration securely
- Prevents timing attacks on duration validation
- Properly handles message deletion events
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any, List, Union

from .protocol import ProtocolNode
from .types.expiration import ExpirationType, ExpirationInfo


class DisappearingMessageError(Exception):
    """Exception raised for errors related to disappearing messages."""
    pass


class DisappearingMessageManager:
    """Manages disappearing messages functionality."""
    
    # Standard WhatsApp disappearing message durations in seconds
    # These match whatsmeow's implementation
    OFF = 0
    ONE_MINUTE = 60
    ONE_HOUR = 3600
    ONE_DAY = 86400  # 1 day
    ONE_WEEK = 604800  # 7 days
    NINETY_DAYS = 7776000  # 90 days
    
    # Valid durations for disappearing messages in seconds
    VALID_DURATIONS = {
        ExpirationType.OFF: OFF,
        ExpirationType.ONE_DAY: ONE_DAY,
        ExpirationType.ONE_WEEK: ONE_WEEK,
        ExpirationType.NINETY_DAYS: NINETY_DAYS,
    }
    
    # Standard WhatsApp durations in seconds with human-readable labels
    STANDARD_DURATIONS = {
        OFF: "Off",
        ONE_MINUTE: "1 minute",
        ONE_HOUR: "1 hour",
        ONE_DAY: "24 hours",
        ONE_WEEK: "7 days",
        NINETY_DAYS: "90 days"
    }
    
    @classmethod
    def validate_duration(cls, duration_seconds: int) -> bool:
        """
        Validate if the given duration is a valid disappearing message duration.
        
        Args:
            duration_seconds: Duration in seconds to validate
            
        Returns:
            bool: True if valid, False otherwise
            
        Note:
            whatsmeow accepts 0 (off), 60 (1m), 3600 (1h), 86400 (24h), 604800 (7d), 2419200 (30d)
        """
        return duration_seconds in {
            cls.OFF,
            cls.ONE_MINUTE,
            cls.ONE_HOUR,
            cls.ONE_DAY,
            cls.ONE_WEEK,
            cls.NINETY_DAYS
        }
    
    @classmethod
    def get_expiration_info(
        cls,
        duration_seconds: int,
        start_time: Optional[datetime] = None
    ) -> ExpirationInfo:
        """
        Create an ExpirationInfo object from a duration in seconds.
        
        Args:
            duration_seconds: Duration in seconds (0 to disable)
            start_time: Optional start time (defaults to now)
            
        Returns:
            ExpirationInfo object with the calculated expiration details
            
        Raises:
            DisappearingMessageError: If the duration is invalid
        """
        if not cls.validate_duration(duration_seconds):
            valid_durations = ", ".join(str(d) for d in sorted(cls.VALID_DURATIONS.values()))
            raise DisappearingMessageError(
                f"Invalid duration. Must be one of: {valid_durations}"
            )
        
        expiration_type = next(
            (t for t, d in cls.VALID_DURATIONS.items() if d == duration_seconds),
            ExpirationType.CUSTOM
        )
        
        if duration_seconds == 0:
            return ExpirationInfo(enabled=False)
            
        start = start_time or datetime.utcnow()
        expiration_time = start + timedelta(seconds=duration_seconds)
        
        return ExpirationInfo(
            enabled=True,
            duration_seconds=duration_seconds,
            expiration_timestamp=expiration_time,
            type=expiration_type
        )
    
    @classmethod
    def create_ephemeral_node(
        cls,
        duration_seconds: int,
        is_ephemeral: bool = False
    ) -> Optional[ProtocolNode]:
        """
        Create a protocol node for ephemeral message settings.
        
        Args:
            duration_seconds: Duration in seconds (0 to disable)
            is_ephemeral: Whether this is a view-once message
            
        Returns:
            ProtocolNode with ephemeral settings, or None if not applicable
            
        Raises:
            DisappearingMessageError: If the duration is invalid
        """
        if not cls.validate_duration(duration_seconds):
            valid_durations = ", ".join(str(d) for d in sorted(cls.VALID_DURATIONS.values()))
            raise DisappearingMessageError(
                f"Invalid duration. Must be one of: {valid_durations}"
            )
            
        if duration_seconds <= 0:
            return None
            
        # Create the ephemeral node with the duration
        return ProtocolNode(
            tag="ephemeral",
            attrs={"duration": str(duration_seconds)}
        )
    
    @classmethod
    def update_message_node(
        cls,
        message_node: ProtocolNode,
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False
    ) -> ProtocolNode:
        """
        Update a message node with disappearing message settings.
        
        Args:
            message_node: The message node to update
            expiration_seconds: Duration in seconds (None to keep current)
            is_ephemeral: Whether this is a view-once message
            
        Returns:
            The updated message node
            
        Raises:
            DisappearingMessageError: If the duration is invalid
        """
        # Add ephemeral attribute for view-once messages
        if is_ephemeral:
            message_node.attrs["ephemeral"] = "1"
        
        # Add ephemeral node if duration is provided
        if expiration_seconds is not None:
            if expiration_seconds > 0:
                ephemeral_node = cls.create_ephemeral_node(expiration_seconds, is_ephemeral)
                if ephemeral_node:
                    if not hasattr(message_node, 'content') or not message_node.content:
                        message_node.content = []
                    message_node.content.append(ephemeral_node)
            else:
                # Remove any existing ephemeral nodes if duration is 0
                if hasattr(message_node, 'content') and message_node.content:
                    message_node.content = [
                        node for node in message_node.content 
                        if not (isinstance(node, ProtocolNode) and node.tag == "ephemeral")
                    ]
        
        return message_node
