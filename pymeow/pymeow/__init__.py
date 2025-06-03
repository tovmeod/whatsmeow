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

from .client import Client as BaseClient
from .types import Message, GroupInfo, PrivacySetting


# Create enhanced Client class with message handling capabilities
class Client(BaseClient):
    """
    Client for WhatsApp Web API with message handling and newsletter capabilities.

    This combines the base Client class with message handling and newsletter mixins,
    similar to how the Device class is enhanced with SignalProtocolMixin.

    The message handling now uses composition via MessageHandler and MessageProcessingHandler
    classes, while maintaining backward compatibility through the mixins.
    """

    # Helper method stubs that should be implemented in the base client or one of the mixins

    def generate_message_id(self):
        """Generate a unique message ID.

        This method should be implemented in the base client.
        """
        raise NotImplementedError("generate_message_id method must be implemented in the base client")


__all__ = [
    'Client',
    'Message',
    'GroupInfo',
    'PrivacySetting',
]
