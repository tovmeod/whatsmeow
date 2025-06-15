"""
Error classes for the application state management.

This module defines custom exception classes for the application state management.
"""

class AppStateError(Exception):
    """Base class for all application state errors."""
    pass

class MissingPreviousSetValueOperationError(AppStateError):
    """Raised when the value MAC of a previous SET operation is missing."""
    def __init__(self, message: str="Missing value MAC of previous SET operation") -> None:
        self.message = message
        super().__init__(self.message)

class MismatchingLTHashError(AppStateError):
    """Raised when there's a mismatching LTHash."""
    def __init__(self, message: str="Mismatching LTHash") -> None:
        self.message = message
        super().__init__(self.message)

class MismatchingPatchMACError(AppStateError):
    """Raised when there's a mismatching patch MAC."""
    def __init__(self, message: str="Mismatching patch MAC") -> None:
        self.message = message
        super().__init__(self.message)

class MismatchingContentMACError(AppStateError):
    """Raised when there's a mismatching content MAC."""
    def __init__(self, message: str="Mismatching content MAC") -> None:
        self.message = message
        super().__init__(self.message)

class MismatchingIndexMACError(AppStateError):
    """Raised when there's a mismatching index MAC."""
    def __init__(self, message: str="Mismatching index MAC") -> None:
        self.message = message
        super().__init__(self.message)

class KeyNotFoundError(AppStateError):
    """Raised when an app state key is not found."""
    def __init__(self) -> None:
        super().__init__("Didn't find app state key")

# For compatibility with code expecting error constants
ErrMissingPreviousSetValueOperation = MissingPreviousSetValueOperationError
ErrMismatchingLTHash = MismatchingLTHashError
ErrMismatchingPatchMAC = MismatchingPatchMACError
ErrMismatchingContentMAC = MismatchingContentMACError
ErrMismatchingIndexMAC = MismatchingIndexMACError
