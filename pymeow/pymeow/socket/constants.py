"""
Socket Constants Module

This module contains constants used for WebSocket communication with WhatsApp servers.
It implements a subset of the Noise protocol framework on top of WebSockets as used by WhatsApp.

Corresponds to the Go file: whatsmeow/socket/constants.go

Note: There shouldn't be any need to manually interact with this module.
The Client class in the top-level pymeow package handles everything.
"""
from ..binary.token import DICT_VERSION

# Origin header for all WhatsApp WebSocket connections
ORIGIN = "https://web.whatsapp.com"

# WebSocket URL for the multidevice protocol
URL = "wss://web.whatsapp.com/ws/chat"

# Noise protocol handshake pattern and parameters
NOISE_START_PATTERN = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"

# WhatsApp magic value used in the connection header
WA_MAGIC_VALUE = 6

# Connection header sent during WebSocket handshake
WA_CONN_HEADER = bytes([ord('W'), ord('A'), WA_MAGIC_VALUE, DICT_VERSION])

# Frame size limits and configuration
FRAME_MAX_SIZE = 2 << 23  # 16MB
FRAME_LENGTH_SIZE = 3  # 3 bytes for frame length

# Error messages
class SocketError(Exception):
    """Base class for socket-related errors."""
    pass

class FrameTooLargeError(SocketError):
    """Raised when a frame exceeds the maximum allowed size."""
    pass

class SocketClosedError(SocketError):
    """Raised when attempting to use a closed socket."""
    pass

class SocketAlreadyOpenError(SocketError):
    """Raised when attempting to open an already open socket."""
    pass
