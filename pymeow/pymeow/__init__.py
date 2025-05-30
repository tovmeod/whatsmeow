"""
pymeow - A Python implementation of the WhatsApp Web multidevice API

This library provides an asynchronous Python interface to the WhatsApp Web API,
compatible with the whatsmeow Go library's protocol implementation.

Package structure and Go equivalents:
- client.py      -> client/*.go (Main client implementation)
- websocket.py   -> socket/*.go (WebSocket connection handling)
- protocol.py    -> binary/*, waBinary/* (Binary protocol implementation)
- types/         -> types/* (Data structures and types)
- exceptions.py  -> errors/errors.go (Error types)
- rate_limiter.py -> Utilities for rate limiting message sending
- client_presence.py -> Presence and chat state handling

This is a direct port of the whatsmeow Go library, maintaining the same
architecture and design patterns where appropriate, while leveraging Python's
asyncio for efficient asynchronous I/O.
"""

__version__ = "0.1.0"

# Re-export presence-related types and enums
from .types.presence import (
    Presence,
    ChatPresence,
    ChatPresenceMedia,
    PresenceEvent,
    ChatPresenceEvent,
)

from .message import MessageHandlingMixin, MessageProcessingMixin
from .client import Client as BaseClient
from .types import Message, GroupInfo, PrivacySetting
from .newsletter import NewsletterMixin

# Create enhanced Client class with message handling capabilities
class Client(BaseClient, MessageHandlingMixin, MessageProcessingMixin, NewsletterMixin):
    """
    Client for WhatsApp Web API with message handling and newsletter capabilities.

    This combines the base Client class with message handling and newsletter mixins,
    similar to how the Device class is enhanced with SignalProtocolMixin.
    """
    pass

    # Helper method stubs that should be implemented in the base client or one of the mixins
    def send_iq(self, *args, **kwargs):
        """Send an IQ request.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("send_iq method must be implemented in the base client")

    def generate_request_id(self):
        """Generate a unique request ID.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("generate_request_id method must be implemented in the base client")

    def cancel_response(self, request_id, response):
        """Cancel waiting for a response.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("cancel_response method must be implemented in the base client")

    def generate_message_id(self):
        """Generate a unique message ID.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("generate_message_id method must be implemented in the base client")

    def send_node(self, node):
        """Send a node to the server.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("send_node method must be implemented in the base client")
    def wait_response(self, request_id):
        """Wait for a response to a request.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("wait_response method must be implemented in the base client")

__all__ = [
    'Client',
    'Message',
    'GroupInfo',
    'PrivacySetting',
    'MessageHandlingMixin',
    'MessageProcessingMixin',
    'NewsletterMixin',
]
