"""
Python port of error types from whatsmeow.

This module defines the exception hierarchy used throughout the pymeow
library, mapping to the error types defined in the original Go implementation.

Go equivalents:
- errors/errors.go: Base error types and error handling utilities
- errors/error_string.go: Error string constants
- errors/error_wrapper.go: Error wrapping functionality

Key differences from the Go implementation:
- Uses Python's built-in exception hierarchy
- Implements Python's exception chaining
- More descriptive error messages with context
- Simplified error handling with try/except
- No need for explicit error checking after each operation

Error hierarchy:
- PymeowError (base class)
  - ConnectionError: Network and connection issues
  - AuthenticationError: Login and auth failures
  - NotFoundError: Requested resource not found
  - RateLimitError: API rate limiting
  - ServerError: Server-side errors with status codes
  - MessageError: Message sending/receiving issues
  - MediaUploadError: Media upload failures
  - GroupError: Group management operations
  - ValidationError: Input validation failures
  - ProtocolError: Protocol parsing/format issues

Usage example:
    try:
        # Code that might raise an exception
        await client.send_message(...)
    except pymeow.NotFoundError:
        print("Requested chat not found")
    except pymeow.RateLimitError as e:
        print(f"Rate limited: {e}")
    except pymeow.PymeowError as e:
        print(f"Unexpected error: {e}")
"""

class PymeowError(Exception):
    """Base exception for all pymeow errors."""
    pass

class ConnectionError(PymeowError):
    """Raised when there is an error connecting to WhatsApp servers."""
    pass

class AuthenticationError(PymeowError):
    """Raised when there is an authentication error."""
    pass

class TimeoutError(PymeowError):
    """Raised when an operation times out."""
    pass

class NotFoundError(PymeowError):
    """Raised when a requested resource is not found."""
    pass

class RateLimitError(PymeowError):
    """Raised when rate limited by WhatsApp servers."""
    pass

class ServerError(PymeowError):
    """Raised when there is an error from the WhatsApp servers."""
    def __init__(self, message: str, status_code: int = 500):
        self.status_code = status_code
        super().__init__(f"Server error (HTTP {status_code}): {message}")

class MessageError(PymeowError):
    """Raised when there is an error sending or processing a message."""
    pass

class MediaUploadError(PymeowError):
    """Raised when there is an error uploading media."""
    pass

class GroupError(PymeowError):
    """Raised when there is an error related to group operations."""
    pass

class ValidationError(PymeowError):
    """Raised when input validation fails."""
    pass

class ProtocolError(PymeowError):
    """Raised when there is an error in the protocol implementation."""
    pass
