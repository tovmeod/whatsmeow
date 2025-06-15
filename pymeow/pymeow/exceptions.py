"""
Exceptions and error handling for the PyMeow WhatsApp Web client.

This module defines custom exceptions used throughout the library.
Port of whatsmeow/errors.go
"""

from typing import Any, Dict, Optional


class PymeowError(Exception):
    """Base exception for all PyMeow errors."""
    pass


# Protocol-related errors
class ProtocolError(PymeowError):
    """Base class for protocol-related errors."""
    pass


class AuthenticationError(PymeowError):
    """Base class for authentication-related errors."""
    pass


# Pre-key related errors
class PreKeyError(PymeowError):
    """Raised when there's an error with pre-key operations."""
    pass


# Connection and session errors
class ErrClientIsNil(PymeowError):
    """Raised when the client is nil."""

    def __init__(self):
        super().__init__("the client is not initialized")


class ErrNoSession(PymeowError):
    """Raised when there's no session available."""

    def __init__(self, action: str = ""):
        if action:
            super().__init__(f"can't {action} without being logged in")
        else:
            super().__init__("no session available")


class ErrIQTimedOut(PymeowError):
    """Raised when an IQ request times out."""

    def __init__(self, request_type: str = ""):
        if request_type:
            super().__init__(f"IQ request {request_type} timed out")
        else:
            super().__init__("IQ request timed out")


class ErrNotConnected(PymeowError):
    """Raised when trying to perform an action that requires a connection."""

    def __init__(self, action: str = ""):
        if action:
            super().__init__(f"can't {action} when not connected")
        else:
            super().__init__("not connected to WhatsApp")


class ErrNotLoggedIn(PymeowError):
    """Raised when trying to perform an action that requires being logged in."""

    def __init__(self, action: str = ""):
        if action:
            super().__init__(f"can't {action} when not logged in")
        else:
            super().__init__("not logged in")


class ErrMessageTimedOut(PymeowError):
    """Raised when a message send times out."""

    def __init__(self, message_id: str = ""):
        if message_id:
            super().__init__(f"message {message_id} send timed out")
        else:
            super().__init__("message send timed out")


class ErrAlreadyConnected(PymeowError):
    """Raised when trying to connect while already connected."""

    def __init__(self):
        super().__init__("already connected")


class ErrQRAlreadyConnected(PymeowError):
    """Raised when trying to get QR code while already connected."""

    def __init__(self):
        super().__init__("already connected, can't get QR code")


class ErrQRStoreContainsID(PymeowError):
    """Raised when the store already contains a device ID."""

    def __init__(self):
        super().__init__("device store already contains a device ID, pairing is not possible")


class NoPushNameError(PymeowError):
    """Raised when push name is required but not set.

    Port of Go's ErrNoPushName: "can't send presence without PushName set"
    """

    def __init__(self):
        super().__init__("can't send presence without PushName set")


class NoPrivacyTokenError(PymeowError):
    """Raised when privacy token is required but not available.

    Port of Go's ErrNoPrivacyToken: "no privacy token stored"
    """

    def __init__(self):
        super().__init__("no privacy token stored")


class ErrAppStateUpdate(PymeowError):
    """Raised when there's an error updating app state."""

    def __init__(self, message: str):
        super().__init__(f"app state update error: {message}")


# Pairing errors
class ErrPairInvalidDeviceIdentityHMAC(AuthenticationError):
    """Raised when device identity HMAC is invalid during pairing."""

    def __init__(self):
        super().__init__("invalid device identity HMAC")


class ErrPairInvalidDeviceSignature(AuthenticationError):
    """Raised when device signature is invalid during pairing."""

    def __init__(self):
        super().__init__("invalid device signature")


class ErrPairRejectedLocally(AuthenticationError):
    """Raised when pairing is rejected locally."""

    def __init__(self):
        super().__init__("pairing was rejected locally")


class PairProtoError(ProtocolError):
    """Raised when there's a protocol error during pairing."""

    def __init__(self, message: str, proto_err: Exception):
        self.message = message
        self.proto_err = proto_err
        super().__init__(f"pairing protocol error: {message}")


class PairDatabaseError(PymeowError):
    """Raised when there's a database error during pairing."""

    def __init__(self, message: str, db_err: Exception):
        self.message = message
        self.db_err = db_err
        super().__init__(f"pairing database error: {message}")


# Profile and group errors
class ErrProfilePictureUnauthorized(AuthenticationError):
    """Raised when not authorized to access profile picture."""

    def __init__(self):
        super().__init__("unauthorized to view profile picture")


class ErrProfilePictureNotSet(PymeowError):
    """Raised when profile picture is not set."""

    def __init__(self):
        super().__init__("profile picture is not set")


class ErrGroupInviteLinkUnauthorized(AuthenticationError):
    """Raised when not authorized to access group invite link."""

    def __init__(self):
        super().__init__("unauthorized to view group invite link")


class ErrNotInGroup(PymeowError):
    """Raised when trying to perform a group action while not in the group."""

    def __init__(self):
        super().__init__("not in group")


class ErrGroupNotFound(PymeowError):
    """Raised when a group is not found."""

    def __init__(self):
        super().__init__("group not found")


class ErrInviteLinkInvalid(PymeowError):
    """Raised when an invite link is invalid."""

    def __init__(self):
        super().__init__("invite link is invalid")


class ErrInviteLinkRevoked(PymeowError):
    """Raised when an invite link has been revoked."""

    def __init__(self):
        super().__init__("invite link has been revoked")


class ErrBusinessMessageLinkNotFound(PymeowError):
    """Raised when a business message link is not found."""

    def __init__(self):
        super().__init__("business message link not found")


class ErrContactQRLinkNotFound(PymeowError):
    """Raised when a contact QR link is not found."""

    def __init__(self):
        super().__init__("contact QR link not found")


class ErrInvalidImageFormat(PymeowError):
    """Raised when image format is invalid."""

    def __init__(self):
        super().__init__("invalid image format")


class ErrMediaNotAvailableOnPhone(PymeowError):
    """Raised when media is not available on phone."""

    def __init__(self):
        super().__init__("media is not available on phone")


class ErrUnknownMediaRetryError(PymeowError):
    """Raised when there's an unknown media retry error."""

    def __init__(self, msg: str):
        super().__init__(msg)


class ErrInvalidDisappearingTimer(PymeowError):
    """Raised when disappearing timer value is invalid."""

    def __init__(self):
        super().__init__("invalid disappearing timer value")


# Broadcast and server errors
class ErrBroadcastListUnsupported(PymeowError):
    """Raised when broadcast lists are not supported."""

    def __init__(self):
        super().__init__("broadcast lists are not supported")


class ErrUnknownServer(PymeowError):
    """Raised when connecting to an unknown server."""

    def __init__(self):
        super().__init__("unknown server")


class ErrRecipientADJID(PymeowError):
    """Raised when recipient has an AD JID."""

    def __init__(self):
        super().__init__("recipient has an AD JID")


class ErrServerReturnedError(ProtocolError):
    """Raised when server returns an error."""

    def __init__(self):
        super().__init__("server returned an error")


class ErrInvalidInlineBotID(PymeowError):
    """Raised when inline bot ID is invalid."""

    def __init__(self):
        super().__init__("invalid inline bot ID")


# Media download errors
class DownloadHTTPError(PymeowError):
    """Raised when there's an HTTP error during media download."""

    def __init__(self, status_code: int, response_body: str = ""):
        self.status_code = status_code
        if response_body:
            super().__init__(f"download failed with HTTP {status_code}: {response_body}")
        else:
            super().__init__(f"download failed with HTTP {status_code}")

    def __eq__(self, other):
        if isinstance(other, DownloadHTTPError):
            return self.status_code == other.status_code
        return False


# Predefined HTTP error instances
ErrMediaDownloadFailedWith403 = DownloadHTTPError(403)
ErrMediaDownloadFailedWith404 = DownloadHTTPError(404)
ErrMediaDownloadFailedWith410 = DownloadHTTPError(410)


class ErrNoURLPresent(PymeowError):
    """Raised when no URL is present for download."""

    def __init__(self):
        super().__init__("no URL present")


class ErrFileLengthMismatch(PymeowError):
    """Raised when file length doesn't match expected."""

    def __init__(self):
        super().__init__("file length mismatch")


class ErrTooShortFile(PymeowError):
    """Raised when file is too short."""

    def __init__(self):
        super().__init__("file too short")


class ErrInvalidMediaHMAC(PymeowError):
    """Raised when media HMAC is invalid."""

    def __init__(self):
        super().__init__("invalid media HMAC")


class ErrInvalidMediaEncSHA256(PymeowError):
    """Raised when media encrypted SHA256 is invalid."""

    def __init__(self):
        super().__init__("invalid media encrypted SHA256")


class ErrInvalidMediaSHA256(PymeowError):
    """Raised when media SHA256 is invalid."""

    def __init__(self):
        super().__init__("invalid media SHA256")


class ErrUnknownMediaType(PymeowError):
    """Raised when media type is unknown."""

    def __init__(self):
        super().__init__("unknown media type")


class ErrNothingDownloadableFound(PymeowError):
    """Raised when nothing downloadable is found."""

    def __init__(self):
        super().__init__("nothing downloadable found")


# Message handling errors
class ErrOriginalMessageSecretNotFound(PymeowError):
    """Raised when original message secret is not found."""

    def __init__(self):
        super().__init__("original message secret not found")


class ErrNotEncryptedReactionMessage(PymeowError):
    """Raised when reaction message is not encrypted."""

    def __init__(self):
        super().__init__("message is not an encrypted reaction message")


class ErrNotEncryptedCommentMessage(PymeowError):
    """Raised when comment message is not encrypted."""

    def __init__(self):
        super().__init__("message is not an encrypted comment message")


class ErrNotPollUpdateMessage(PymeowError):
    """Raised when message is not a poll update."""

    def __init__(self):
        super().__init__("message is not a poll update message")


# IQ error handling
class WrappedIQError(PymeowError):
    """Wrapper for IQ errors with human-readable messages."""

    def __init__(self, human_error: str, iq_error: 'IQError'):
        self.human_error = human_error
        self.iq_error = iq_error
        super().__init__(human_error)


def wrap_iq_error(human_error: str, iq_error: 'IQError') -> WrappedIQError:
    """Wrap an IQ error with a human-readable message."""
    return WrappedIQError(human_error, iq_error)


class IQError(ProtocolError):
    """Represents an IQ error response."""

    def __init__(self, code: int, text: str, error_node: 'Node', raw_node: 'Node'):
        self.code = code
        self.text = text
        self.error_node = error_node
        self.raw_node = raw_node

        error_type = ""
        if 400 <= code < 500:
            error_type = "client"
        elif 500 <= code < 600:
            error_type = "server"
        else:
            error_type = "unknown"

        if text:
            super().__init__(f"IQ {error_type} error {code}: {text}")
        else:
            super().__init__(f"IQ {error_type} error {code}")

    def __eq__(self, other):
        if isinstance(other, IQError):
            return (self.code == other.code and
                   self.text == other.text and
                   self.error_node == other.error_node)
        return False


# Predefined IQ error instances
ErrIQBadRequest = IQError(400, "bad-request", None, None)
ErrIQNotAuthorized = IQError(401, "not-authorized", None, None)
ErrIQForbidden = IQError(403, "forbidden", None, None)
ErrIQNotFound = IQError(404, "not-found", None, None)
ErrIQNotAllowed = IQError(405, "not-allowed", None, None)
ErrIQNotAcceptable = IQError(406, "not-acceptable", None, None)
ErrIQGone = IQError(410, "gone", None, None)
ErrIQResourceLimit = IQError(419, "resource-limit", None, None)
ErrIQLocked = IQError(423, "locked", None, None)
ErrIQRateOverLimit = IQError(429, "rate-over-limit", None, None)
ErrIQInternalServerError = IQError(500, "internal-server-error", None, None)
ErrIQServiceUnavailable = IQError(503, "service-unavailable", None, None)
ErrIQPartialServerError = IQError(520, "partial-server-error", None, None)


def parse_iq_error(error_node: 'Node') -> IQError:
    """Parse an IQ error from a node."""
    code = 500  # default to server error
    text = ""

    if error_node.attrs:
        code_str = error_node.attrs.get("code", "500")
        try:
            code = int(code_str)
        except ValueError:
            code = 500

        text = error_node.attrs.get("text", "")

    # Try to get more specific error info from child nodes
    if hasattr(error_node, 'children') and error_node.children:
        for child in error_node.children:
            if hasattr(child, 'tag'):
                if not text:
                    text = child.tag
                break

    return IQError(code, text, error_node, error_node)


# XML and parsing errors
class ElementMissingError(ProtocolError):
    """Raised when a required XML element is missing."""

    def __init__(self, tag: str, in_location: str):
        self.tag = tag
        self.in_location = in_location
        super().__init__(f"missing element {tag} in {in_location}")


# Disconnection errors
class DisconnectedError(ProtocolError):
    """Raised when connection is lost."""

    def __init__(self, node: 'Node', action: str):
        self.node = node
        self.action = action
        super().__init__(f"disconnected while {action}")

    def __eq__(self, other):
        if isinstance(other, DisconnectedError):
            return self.node == other.node and self.action == other.action
        return False


# Special disconnection marker
ErrIQDisconnected = DisconnectedError(None, "waiting for IQ response")
