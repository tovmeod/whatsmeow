"""
Message utility functions for PyMeow.

This module provides utility functions for creating and managing different types of
WhatsApp messages, including disappearing messages.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging

from .protocol import ProtocolNode
from .types.expiration import ExpirationType, ExpirationInfo

logger = logging.getLogger(__name__)

class MessageUtils:
    """Utility class for message-related operations."""
    
    # Valid durations for disappearing messages in seconds
    VALID_DURATIONS = {
        ExpirationType.OFF: 0,
        ExpirationType.ONE_DAY: 86400,  # 1 day
        ExpirationType.ONE_WEEK: 604800,  # 7 days
        ExpirationType.NINETY_DAYS: 7776000,  # 90 days
    }
    
    @classmethod
    def validate_duration(cls, duration_seconds: int) -> bool:
        """Check if the given duration is valid for disappearing messages."""
        return duration_seconds in cls.VALID_DURATIONS.values()
    
    @classmethod
    def create_text_message_node(
        cls,
        to: str,
        content: str,
        message_id: str,
        quoted_message_id: Optional[str] = None,
        mentions: Optional[List[str]] = None,
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False
    ) -> ProtocolNode:
        """
        Create a text message node with support for disappearing messages.
        
        Args:
            to: Recipient JID
            content: Message content
            message_id: Unique message ID
            quoted_message_id: Optional quoted message ID
            mentions: Optional list of mentioned JIDs
            expiration_seconds: Duration in seconds for disappearing message
            is_ephemeral: Whether this is a view-once message
            
        Returns:
            ProtocolNode: The constructed message node
        """
        # Create message body node
        body_node = ProtocolNode(
            tag="body",
            content=content
        )

        # Add quoted message if provided
        if quoted_message_id:
            quoted_node = ProtocolNode(
                tag="quoted",
                attrs={"id": quoted_message_id}
            )
            body_node.add_child(quoted_node)

        # Add mentions if provided
        if mentions:
            mention_nodes = [
                ProtocolNode("mention", attrs={"jid": jid})
                for jid in mentions or []
            ]
            mentions_node = ProtocolNode("mentions", content=mention_nodes)
            body_node.add_child(mentions_node)

        # Create message node
        message_node = ProtocolNode(
            tag="message",
            attrs={
                "id": message_id,
                "type": "text",
                "to": to,
                "t": str(int(datetime.now().timestamp()))
            },
            content=[body_node]
        )

        # Add ephemeral settings if needed
        if expiration_seconds is not None or is_ephemeral:
            cls._add_ephemeral_settings(
                message_node,
                expiration_seconds=expiration_seconds,
                is_ephemeral=is_ephemeral
            )

        return message_node
    
    @classmethod
    def _add_ephemeral_settings(
        cls,
        message_node: ProtocolNode,
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False
    ) -> None:
        """
        Add ephemeral message settings to a message node.
        
        Args:
            message_node: The message node to modify
            expiration_seconds: Duration in seconds for disappearing message
            is_ephemeral: Whether this is a view-once message
        """
        if expiration_seconds is not None and not cls.validate_duration(expiration_seconds):
            valid_durations = ", ".join(str(d) for d in sorted(cls.VALID_DURATIONS.values()))
            logger.warning(
                f"Invalid disappearing message duration: {expiration_seconds}. "
                f"Must be one of: {valid_durations}"
            )
            expiration_seconds = None
        
        if is_ephemeral:
            message_node.attrs["ephemeral"] = "1"
        
        if expiration_seconds and expiration_seconds > 0:
            ephemeral_node = ProtocolNode(
                tag="ephemeral",
                attrs={"duration": str(expiration_seconds)}
            )
            if not hasattr(message_node, 'content'):
                message_node.content = []
            message_node.content.append(ephemeral_node)
