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

class ClientError(PymeowError):
    """Raised when there is a client-side error."""
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

class PreKeyError(PymeowError):
    """Raised when there is an error related to pre-keys."""
    pass

class ElementMissingError(ProtocolError):
    """Raised when an expected XML element is missing from a server response.

    This corresponds to Go's ElementMissingError and is used when parsing
    server responses that are missing required XML elements.
    """

    def __init__(self, tag: str, location: str):
        self.tag = tag
        self.location = location
        super().__init__(f"Missing element '{tag}' in {location}")

# IQ (Info Query) Error Classes
class IQError(ProtocolError):
    """Base class for Info Query related errors."""
    pass

class ErrIQNotAcceptable(IQError):
    """Raised when an IQ request is not acceptable (406 status)."""
    pass

class ErrIQNotFound(IQError):
    """Raised when an IQ request returns not found (404 status)."""
    pass

class ErrIQForbidden(IQError):
    """Raised when an IQ request is forbidden (403 status)."""
    pass

class ErrIQGone(IQError):
    """Raised when an IQ request returns gone (410 status)."""
    pass

class ErrIQNotAuthorized(IQError):
    """Raised when an IQ request is not authorized (401 status)."""
    pass

# Media Error Classes
class ErrInvalidImageFormat(MediaUploadError):
    """Raised when an image format is invalid for upload."""
    pass

# Group-specific Error Classes
class ErrGroupNotFound(GroupError):
    """Raised when a group is not found."""
    pass

class ErrNotInGroup(GroupError):
    """Raised when trying to perform an action on a group the user is not in."""
    pass

class ErrGroupInviteLinkUnauthorized(GroupError):
    """Raised when unauthorized to access a group invite link."""
    pass

class ErrInviteLinkRevoked(GroupError):
    """Raised when a group invite link has been revoked."""
    pass

class ErrInviteLinkInvalid(GroupError):
    """Raised when a group invite link is invalid."""
    pass

# Message Secret Error Classes
class OriginalMessageSecretNotFound(PymeowError):
    """Raised when the original message secret key is not found."""
    pass

class NotEncryptedReactionMessage(PymeowError):
    """Raised when trying to decrypt a non-encrypted reaction message."""
    pass

class NotEncryptedCommentMessage(PymeowError):
    """Raised when trying to decrypt a non-encrypted comment message."""
    pass

class NotPollUpdateMessage(PymeowError):
    """Raised when trying to decrypt poll vote from a non-poll update message."""
    pass

class NoPushNameError(PymeowError):
    """Raised when trying to send presence without a push name."""
    pass

class NoPrivacyTokenError(PymeowError):
    """Raised when trying to subscribe to presence without a privacy token."""
    pass

# QR Channel Error Classes
class ClientIsNilError(ClientError):
    """Raised when trying to get a QR channel with a nil client."""
    pass

class QRAlreadyConnectedError(ClientError):
    """Raised when trying to get a QR channel for an already connected client."""
    pass

class QRStoreContainsIDError(ClientError):
    """Raised when trying to get a QR channel for a store that already contains an ID."""
    pass
