"""Test binary protocol error classes."""
import pytest

from ..pymeow.binary.errors import (
    BinaryError,
    ErrInvalidJIDType,
    ErrInvalidNode,
    ErrInvalidToken,
    ErrInvalidType,
    ErrNonStringKey,
    InvalidJIDTypeError,
    InvalidNodeError,
    InvalidTokenError,
    InvalidTypeError,
    NonStringKeyError,
)


def test_binary_error_base_class():
    """Test that BinaryError is a subclass of Exception."""
    assert issubclass(BinaryError, Exception)

    # Test that we can instantiate it
    error = BinaryError("Test error")
    assert str(error) == "Test error"

def test_specific_error_classes():
    """Test that specific error classes are subclasses of BinaryError."""
    assert issubclass(InvalidTypeError, BinaryError)
    assert issubclass(InvalidJIDTypeError, BinaryError)
    assert issubclass(InvalidNodeError, BinaryError)
    assert issubclass(InvalidTokenError, BinaryError)
    assert issubclass(NonStringKeyError, BinaryError)

    # Test that we can instantiate them with default messages
    assert str(InvalidTypeError()) == "Unsupported payload type"
    assert str(InvalidJIDTypeError()) == "Invalid JID type"
    assert str(InvalidNodeError()) == "Invalid node"
    assert str(InvalidTokenError()) == "Invalid token with tag"
    assert str(NonStringKeyError()) == "Non-string key"

    # Test that we can instantiate them with custom messages
    assert str(InvalidTypeError("Custom message")) == "Custom message"
    assert str(InvalidJIDTypeError("Custom message")) == "Custom message"
    assert str(InvalidNodeError("Custom message")) == "Custom message"
    assert str(InvalidTokenError("Custom message")) == "Custom message"
    assert str(NonStringKeyError("Custom message")) == "Custom message"

def test_error_constants():
    """Test that error constants are the correct exception classes."""
    assert ErrInvalidType is InvalidTypeError
    assert ErrInvalidJIDType is InvalidJIDTypeError
    assert ErrInvalidNode is InvalidNodeError
    assert ErrInvalidToken is InvalidTokenError
    assert ErrNonStringKey is NonStringKeyError

    # Test raising errors using the constants
    with pytest.raises(InvalidTypeError):
        raise ErrInvalidType()

    with pytest.raises(InvalidJIDTypeError):
        raise ErrInvalidJIDType()

    with pytest.raises(InvalidNodeError):
        raise ErrInvalidNode()

    with pytest.raises(InvalidTokenError):
        raise ErrInvalidToken()

    with pytest.raises(NonStringKeyError):
        raise ErrNonStringKey()
