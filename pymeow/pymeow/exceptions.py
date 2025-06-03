"""
Python port of error types from whatsmeow.

This module defines the exception hierarchy used throughout the pymeow
library, mapping to the error types defined in the original Go implementation.

Go equivalent: errors/errors.go
"""

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .binary.node import Node


class PymeowError(Exception):
    """Base exception for all pymeow errors."""
    pass


# Miscellaneous errors
class ErrClientIsNil(PymeowError):
    """Raised when client is nil."""

    def __init__(self):
        super().__init__("client is nil")


class ErrNoSession(PymeowError):
    """Raised when can't encrypt message for device: no signal session established."""

    def __init__(self):
        super().__init__("can't encrypt message for device: no signal session established")


class ErrIQTimedOut(PymeowError):
    """Raised when info query timed out."""

    def __init__(self):
        super().__init__("info query timed out")


class ErrNotConnected(PymeowError):
    """Raised when websocket not connected."""

    def __init__(self):
        super().__init__("websocket not connected")


class ErrNotLoggedIn(PymeowError):
    """Raised when the store doesn't contain a device JID."""

    def __init__(self):
        super().__init__("the store doesn't contain a device JID")


class ErrMessageTimedOut(PymeowError):
    """Raised when timed out waiting for message send response."""

    def __init__(self):
        super().__init__("timed out waiting for message send response")


class ErrAlreadyConnected(PymeowError):
    """Raised when websocket is already connected."""

    def __init__(self):
        super().__init__("websocket is already connected")


class ErrQRAlreadyConnected(PymeowError):
    """Raised when GetQRChannel must be called before connecting."""

    def __init__(self):
        super().__init__("GetQRChannel must be called before connecting")


class ErrQRStoreContainsID(PymeowError):
    """Raised when GetQRChannel can only be called when there's no user ID in the client's Store."""

    def __init__(self):
        super().__init__("GetQRChannel can only be called when there's no user ID in the client's Store")


class ErrNoPushName(PymeowError):
    """Raised when can't send presence without PushName set."""

    def __init__(self):
        super().__init__("can't send presence without PushName set")


class ErrNoPrivacyToken(PymeowError):
    """Raised when no privacy token stored."""

    def __init__(self):
        super().__init__("no privacy token stored")


class ErrAppStateUpdate(PymeowError):
    """Raised when server returned error updating app state."""

    def __init__(self):
        super().__init__("server returned error updating app state")


# Pairing errors
class ErrPairInvalidDeviceIdentityHMAC(PymeowError):
    """Raised when invalid device identity HMAC in pair success message."""

    def __init__(self):
        super().__init__("invalid device identity HMAC in pair success message")


class ErrPairInvalidDeviceSignature(PymeowError):
    """Raised when invalid device signature in pair success message."""

    def __init__(self):
        super().__init__("invalid device signature in pair success message")


class ErrPairRejectedLocally(PymeowError):
    """Raised when local PrePairCallback rejected pairing."""

    def __init__(self):
        super().__init__("local PrePairCallback rejected pairing")


class PairProtoError(PymeowError):
    """Included in an events.PairError if the pairing failed due to a protobuf error."""

    def __init__(self, message: str, proto_err: Exception):
        self.message = message
        self.proto_err = proto_err
        super().__init__(f"{message}: {proto_err}")


class PairDatabaseError(PymeowError):
    """Included in an events.PairError if the pairing failed due to being unable to save credentials."""

    def __init__(self, message: str, db_err: Exception):
        self.message = message
        self.db_err = db_err
        super().__init__(f"{message}: {db_err}")


# Profile and media errors
class ErrProfilePictureUnauthorized(PymeowError):
    """Raised when the user has hidden their profile picture from you."""

    def __init__(self):
        super().__init__("the user has hidden their profile picture from you")


class ErrProfilePictureNotSet(PymeowError):
    """Raised when that user or group does not have a profile picture."""

    def __init__(self):
        super().__init__("that user or group does not have a profile picture")


class ErrGroupInviteLinkUnauthorized(PymeowError):
    """Raised when you don't have the permission to get the group's invite link."""

    def __init__(self):
        super().__init__("you don't have the permission to get the group's invite link")


class ErrNotInGroup(PymeowError):
    """Raised when you're not participating in that group."""

    def __init__(self):
        super().__init__("you're not participating in that group")


class ErrGroupNotFound(PymeowError):
    """Raised when that group does not exist."""

    def __init__(self):
        super().__init__("that group does not exist")


class ErrInviteLinkInvalid(PymeowError):
    """Raised when that group invite link is not valid."""

    def __init__(self):
        super().__init__("that group invite link is not valid")


class ErrInviteLinkRevoked(PymeowError):
    """Raised when that group invite link has been revoked."""

    def __init__(self):
        super().__init__("that group invite link has been revoked")


class ErrBusinessMessageLinkNotFound(PymeowError):
    """Raised when that business message link does not exist or has been revoked."""

    def __init__(self):
        super().__init__("that business message link does not exist or has been revoked")


class ErrContactQRLinkNotFound(PymeowError):
    """Raised when that contact QR link does not exist or has been revoked."""

    def __init__(self):
        super().__init__("that contact QR link does not exist or has been revoked")


class ErrInvalidImageFormat(PymeowError):
    """Raised when the given data is not a valid image."""

    def __init__(self):
        super().__init__("the given data is not a valid image")


class ErrMediaNotAvailableOnPhone(PymeowError):
    """Raised when media no longer available on phone."""

    def __init__(self):
        super().__init__("media no longer available on phone")


class ErrUnknownMediaRetryError(PymeowError):
    """Raised when unknown media retry error."""

    def __init__(self):
        super().__init__("unknown media retry error")


class ErrInvalidDisappearingTimer(PymeowError):
    """Raised when invalid disappearing timer provided."""

    def __init__(self):
        super().__init__("invalid disappearing timer provided")


# Message sending errors
class ErrBroadcastListUnsupported(PymeowError):
    """Raised when sending to non-status broadcast lists is not yet supported."""

    def __init__(self):
        super().__init__("sending to non-status broadcast lists is not yet supported")


class ErrUnknownServer(PymeowError):
    """Raised when can't send message to unknown server."""

    def __init__(self):
        super().__init__("can't send message to unknown server")


class ErrRecipientADJID(PymeowError):
    """Raised when message recipient must be a user JID with no device part."""

    def __init__(self):
        super().__init__("message recipient must be a user JID with no device part")


class ErrServerReturnedError(PymeowError):
    """Raised when server returned error."""

    def __init__(self):
        super().__init__("server returned error")


class ErrInvalidInlineBotID(PymeowError):
    """Raised when invalid inline bot ID."""

    def __init__(self):
        super().__init__("invalid inline bot ID")


# Download errors
class DownloadHTTPError(PymeowError):
    """Raised when download failed with HTTP error."""

    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"download failed with status code {status_code}")

    def __eq__(self, other):
        """Allow comparison with other DownloadHTTPError instances."""
        return isinstance(other, DownloadHTTPError) and self.status_code == other.status_code


# Predefined download errors
ErrMediaDownloadFailedWith403 = DownloadHTTPError(403)
ErrMediaDownloadFailedWith404 = DownloadHTTPError(404)
ErrMediaDownloadFailedWith410 = DownloadHTTPError(410)


class ErrNoURLPresent(PymeowError):
    """Raised when no url present."""

    def __init__(self):
        super().__init__("no url present")


class ErrFileLengthMismatch(PymeowError):
    """Raised when file length does not match."""

    def __init__(self):
        super().__init__("file length does not match")


class ErrTooShortFile(PymeowError):
    """Raised when file too short."""

    def __init__(self):
        super().__init__("file too short")


class ErrInvalidMediaHMAC(PymeowError):
    """Raised when invalid media hmac."""

    def __init__(self):
        super().__init__("invalid media hmac")


class ErrInvalidMediaEncSHA256(PymeowError):
    """Raised when hash of media ciphertext doesn't match."""

    def __init__(self):
        super().__init__("hash of media ciphertext doesn't match")


class ErrInvalidMediaSHA256(PymeowError):
    """Raised when hash of media plaintext doesn't match."""

    def __init__(self):
        super().__init__("hash of media plaintext doesn't match")


class ErrUnknownMediaType(PymeowError):
    """Raised when unknown media type."""

    def __init__(self):
        super().__init__("unknown media type")


class ErrNothingDownloadableFound(PymeowError):
    """Raised when didn't find any attachments in message."""

    def __init__(self):
        super().__init__("didn't find any attachments in message")


# Message secret errors
class ErrOriginalMessageSecretNotFound(PymeowError):
    """Raised when original message secret key not found."""

    def __init__(self):
        super().__init__("original message secret key not found")


class ErrNotEncryptedReactionMessage(PymeowError):
    """Raised when given message isn't an encrypted reaction message."""

    def __init__(self):
        super().__init__("given message isn't an encrypted reaction message")


class ErrNotEncryptedCommentMessage(PymeowError):
    """Raised when given message isn't an encrypted comment message."""

    def __init__(self):
        super().__init__("given message isn't an encrypted comment message")


class ErrNotPollUpdateMessage(PymeowError):
    """Raised when given message isn't a poll update message."""

    def __init__(self):
        super().__init__("given message isn't a poll update message")


# Wrapper for IQ errors with human-readable messages
class WrappedIQError(PymeowError):
    """Wrapper for IQ errors with human-readable messages."""

    def __init__(self, human_error: Exception, iq_error: Exception):
        self.human_error = human_error
        self.iq_error = iq_error
        super().__init__(str(human_error))


def wrap_iq_error(human_error: Exception, iq_error: Exception) -> WrappedIQError:
    """Wrap an IQ error with a human-readable error."""
    return WrappedIQError(human_error, iq_error)


# IQ Error implementation
class IQError(PymeowError):
    """Generic error container for info queries."""

    def __init__(self, code: int = 0, text: str = "", error_node: Optional['Node'] = None, raw_node: Optional['Node'] = None):
        self.code = code
        self.text = text
        self.error_node = error_node
        self.raw_node = raw_node

        if code == 0:
            if error_node is not None:
                super().__init__(f"info query returned unknown error: {error_node.xml_string()}")
            elif raw_node is not None:
                super().__init__(f"info query returned unexpected response: {raw_node.xml_string()}")
            else:
                super().__init__("unknown info query error")
        else:
            super().__init__(f"info query returned status {code}: {text}")

    def __eq__(self, other):
        """Allow comparison with other IQError instances."""
        if not isinstance(other, IQError):
            return False
        if self.code != 0 and other.code != 0:
            return other.code == self.code and other.text == self.text
        elif self.error_node is not None and other.error_node is not None:
            return self.error_node.xml_string() == other.error_node.xml_string()
        else:
            return False


# Common IQ errors for use with equality comparison
ErrIQBadRequest = IQError(400, "bad-request")
ErrIQNotAuthorized = IQError(401, "not-authorized")
ErrIQForbidden = IQError(403, "forbidden")
ErrIQNotFound = IQError(404, "item-not-found")
ErrIQNotAllowed = IQError(405, "not-allowed")
ErrIQNotAcceptable = IQError(406, "not-acceptable")
ErrIQGone = IQError(410, "gone")
ErrIQResourceLimit = IQError(419, "resource-limit")
ErrIQLocked = IQError(423, "locked")
ErrIQRateOverLimit = IQError(429, "rate-overlimit")
ErrIQInternalServerError = IQError(500, "internal-server-error")
ErrIQServiceUnavailable = IQError(503, "service-unavailable")
ErrIQPartialServerError = IQError(530, "partial-server-error")


def parse_iq_error(node: 'Node') -> IQError:
    """
    Parse an IQ error node into an IQError exception.

    Args:
        node: The error node to parse

    Returns:
        An IQError instance
    """
    error_node = None
    code = 0
    text = ""

    error_child, found = node.get_optional_child_by_tag("error")
    if found and error_child:
        error_node = error_child
        ag = error_child.attr_getter()
        code = ag.optional_int("code")
        text = ag.optional_string("text")

    return IQError(code=code, text=text, error_node=error_node, raw_node=node)


# ElementMissingError is returned by various functions that parse XML elements when a required element is missing.
class ElementMissingError(PymeowError):
    """Raised when an expected XML element is missing from a server response."""

    def __init__(self, tag: str, in_location: str):
        self.tag = tag
        self.in_location = in_location
        super().__init__(f"missing <{tag}> element in {in_location}")


# DisconnectedError is returned if the websocket disconnects before an info query or other request gets a response.
class DisconnectedError(PymeowError):
    """Returned if the websocket disconnects before an info query or other request gets a response."""

    def __init__(self, action: str, node: Optional['Node'] = None):
        self.action = action
        self.node = node
        super().__init__(f"websocket disconnected before {action} returned response")

    def __eq__(self, other):
        """Allow comparison with other DisconnectedError instances."""
        return isinstance(other, DisconnectedError) and other.action == self.action


# Predefined disconnected error
ErrIQDisconnected = DisconnectedError("info query")
