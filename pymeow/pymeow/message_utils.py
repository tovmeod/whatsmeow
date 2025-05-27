"""
Message utility functions for PyMeow.

This module provides utility functions for creating and managing different types of
WhatsApp messages, including disappearing messages.
"""
from typing import List, Optional
from datetime import datetime
import logging

from .protocol import ProtocolNode
from .types.expiration import ExpirationType
# Import generated Protobuf classes
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
# JID might be needed if 'to' can be a JID object, ensure string conversion
from ..types.jid import JID


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
        to: str, # Assuming 'to' is already a string JID, e.g., "number@s.whatsapp.net"
        content: str,
        message_id: str,
        quoted_message_id: Optional[str] = None,
        mentions: Optional[List[str]] = None, # Assuming mentions are string JIDs
        expiration_seconds: Optional[int] = None,
        is_ephemeral: bool = False # For view-once
    ) -> ProtocolNode:
        """
        Create a text message node using Protobuf serialization.
        
        Args:
            to: Recipient JID string
            content: Message content
            message_id: Unique message ID
            quoted_message_id: Optional quoted message ID
            mentions: Optional list of mentioned JID strings
            expiration_seconds: Duration in seconds for disappearing message
            is_ephemeral: Whether this is a view-once message
            
        Returns:
            ProtocolNode: The constructed message node
        """
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.conversation = content
        
        context_info_modified = False

        if quoted_message_id:
            # Accessing sub-message fields directly creates them if not present
            proto_msg.context_info.stanza_id = quoted_message_id
            context_info_modified = True
            # Ensure participant is set if quoting a group message, client needs to provide this if relevant
            # For simplicity, if quoted_message_id implies a group, participant should be part of ContextInfo
            # This example assumes direct message quoting or participant is handled by caller if needed in ContextInfo

        if mentions:
            # Ensure context_info is initialized if not already by quoted_message_id
            if not context_info_modified: # Check if context_info was already accessed
                 _ = proto_msg.context_info # Access to ensure it's created
            proto_msg.context_info.mentioned_jid.extend(mentions)
            context_info_modified = True

        if expiration_seconds is not None and cls.validate_duration(expiration_seconds) and expiration_seconds > 0:
            # Ensure context_info is initialized
            if not context_info_modified:
                 _ = proto_msg.context_info # Access to ensure it's created
            proto_msg.context_info.ephemeral_expiration = expiration_seconds
            proto_msg.context_info.ephemeral_setting_timestamp = int(datetime.now().timestamp())
            # No need to set context_info_modified to True here, as serialization happens once at the end
        elif expiration_seconds is not None: # Invalid duration
             logger.warning(
                f"Invalid disappearing message duration: {expiration_seconds}. "
                f"Must be one of: {cls.VALID_DURATIONS.values()}"
            )


        # Serialize the Protobuf message to bytes
        serialized_payload = proto_msg.SerializeToString()

        # Construct the outer ProtocolNode
        attrs = {
            "id": message_id,
            "to": str(to), # Ensure 'to' is string (it should be based on type hint)
            "type": "text", 
            "t": str(int(datetime.now().timestamp()))
        }

        if is_ephemeral: # For view-once
            attrs["ephemeral"] = "1"
            
        final_message_node = ProtocolNode(
            tag="message",
            attrs=attrs,
            content=serialized_payload # Content is now bytes
        )

        return final_message_node

    # _add_ephemeral_settings method is now removed as its logic is integrated.
    # The part for <ephemeral duration="X"/> child node is handled by
    # proto_msg.context_info.ephemeral_expiration and ephemeral_setting_timestamp.
    # The part for ephemeral="1" attribute is handled directly in create_text_message_node.
    # Validation logging is also moved.
