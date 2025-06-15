"""
Error classes for the binary XML decoder.

This module defines custom exception classes for the binary XML decoder.
"""

class BinaryError(Exception):
    """Base class for all binary XML decoder errors."""
    pass

class InvalidTypeError(BinaryError):
    """Raised when an unsupported payload type is encountered."""
    def __init__(self, message: str="Unsupported payload type") -> None:
        self.message = message
        super().__init__(self.message)

class InvalidJIDTypeError(BinaryError):
    """Raised when an invalid JID type is encountered."""
    def __init__(self, message: str="Invalid JID type") -> None:
        self.message = message
        super().__init__(self.message)

class InvalidNodeError(BinaryError):
    """Raised when an invalid node is encountered."""
    def __init__(self, message: str="Invalid node") -> None:
        self.message = message
        super().__init__(self.message)

class InvalidTokenError(BinaryError):
    """Raised when an invalid token with tag is encountered."""
    def __init__(self, message: str="Invalid token with tag") -> None:
        self.message = message
        super().__init__(self.message)

class NonStringKeyError(BinaryError):
    """Raised when a non-string key is encountered."""
    def __init__(self, message: str="Non-string key") -> None:
        self.message = message
        super().__init__(self.message)

# For compatibility with code expecting error constants
ErrInvalidType = InvalidTypeError
ErrInvalidJIDType = InvalidJIDTypeError
ErrInvalidNode = InvalidNodeError
ErrInvalidToken = InvalidTokenError
ErrNonStringKey = NonStringKeyError
