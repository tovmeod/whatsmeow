"""Test application state error classes."""
import pytest

from py.pymeow.appstate import (
    AppStateError,
    ErrKeyNotFound,
    ErrMismatchingContentMAC,
    ErrMismatchingIndexMAC,
    ErrMismatchingLTHash,
    ErrMismatchingPatchMAC,
    ErrMissingPreviousSetValueOperation,
    KeyNotFoundError,
    MismatchingContentMACError,
    MismatchingIndexMACError,
    MismatchingLTHashError,
    MismatchingPatchMACError,
    MissingPreviousSetValueOperationError,
)


def test_appstate_error_base_class():
    """Test that AppStateError is a subclass of Exception."""
    assert issubclass(AppStateError, Exception)

    # Test that we can instantiate it
    error = AppStateError("Test error")
    assert str(error) == "Test error"

def test_specific_error_classes():
    """Test that specific error classes are subclasses of AppStateError."""
    assert issubclass(MissingPreviousSetValueOperationError, AppStateError)
    assert issubclass(MismatchingLTHashError, AppStateError)
    assert issubclass(MismatchingPatchMACError, AppStateError)
    assert issubclass(MismatchingContentMACError, AppStateError)
    assert issubclass(MismatchingIndexMACError, AppStateError)
    assert issubclass(KeyNotFoundError, AppStateError)

    # Test that we can instantiate them with default messages
    assert str(MissingPreviousSetValueOperationError()) == "Missing value MAC of previous SET operation"
    assert str(MismatchingLTHashError()) == "Mismatching LTHash"
    assert str(MismatchingPatchMACError()) == "Mismatching patch MAC"
    assert str(MismatchingContentMACError()) == "Mismatching content MAC"
    assert str(MismatchingIndexMACError()) == "Mismatching index MAC"
    assert str(KeyNotFoundError()) == "Didn't find app state key"

    # Test that we can instantiate them with custom messages
    assert str(MissingPreviousSetValueOperationError("Custom message")) == "Custom message"
    assert str(MismatchingLTHashError("Custom message")) == "Custom message"
    assert str(MismatchingPatchMACError("Custom message")) == "Custom message"
    assert str(MismatchingContentMACError("Custom message")) == "Custom message"
    assert str(MismatchingIndexMACError("Custom message")) == "Custom message"
    assert str(KeyNotFoundError("Custom message")) == "Custom message"

def test_error_constants():
    """Test that error constants are the correct exception classes."""
    assert ErrMissingPreviousSetValueOperation is MissingPreviousSetValueOperationError
    assert ErrMismatchingLTHash is MismatchingLTHashError
    assert ErrMismatchingPatchMAC is MismatchingPatchMACError
    assert ErrMismatchingContentMAC is MismatchingContentMACError
    assert ErrMismatchingIndexMAC is MismatchingIndexMACError
    assert ErrKeyNotFound is KeyNotFoundError

    # Test raising errors using the constants
    with pytest.raises(MissingPreviousSetValueOperationError):
        raise ErrMissingPreviousSetValueOperation()

    with pytest.raises(MismatchingLTHashError):
        raise ErrMismatchingLTHash()

    with pytest.raises(MismatchingPatchMACError):
        raise ErrMismatchingPatchMAC()

    with pytest.raises(MismatchingContentMACError):
        raise ErrMismatchingContentMAC()

    with pytest.raises(MismatchingIndexMACError):
        raise ErrMismatchingIndexMAC()

    with pytest.raises(KeyNotFoundError):
        raise ErrKeyNotFound()
