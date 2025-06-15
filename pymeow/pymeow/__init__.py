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

