"""

Port of whatsmeow/binary/attrs.go
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .node import Node

if TYPE_CHECKING:
    from ..types import JID

# Type alias for attributes (equivalent to Go's Attrs = map[string]any)
Attrs = Dict[str, Any]


class AttrUtility:
    """
    AttrUtility is a helper struct for reading multiple XML attributes and checking for errors afterwards.

    The functions return values directly and append any decoding errors to the Errors slice. The
    slice can then be checked after all necessary attributes are read, instead of having to check
    each attribute for errors separately.
    """

    def __init__(self, attrs: Attrs):
        self.attrs = attrs
        self.errors: List[Exception] = []  # todo: just raise instead of collecting

    def get_jid(self, key: str, require: bool) -> Tuple['JID', bool]:
        """Get JID attribute with error handling."""
        from ..types import JID
        if key not in self.attrs:
            if require:
                self.errors.append(ValueError(f"didn't find required JID attribute '{key}'"))
            return JID(), False

        val = self.attrs[key]
        if isinstance(val, JID):
            return val, True

        # Try to parse as JID if it's a string
        if isinstance(val, str):
            try:
                jid = JID.from_string(val)
                return jid, True
            except Exception as e:
                self.errors.append(ValueError(f"failed to parse JID in attribute '{key}': {e}"))
                return JID(), False

        self.errors.append(TypeError(f"expected attribute '{key}' to be JID, but was {type(val).__name__}"))
        return JID(), False

    def optional_jid(self, key: str) -> Optional['JID']:
        """
        OptionalJID returns the JID under the given key. If there's no valid JID under the given key, this will return None.
        However, if the attribute is completely missing, this will not store an error.
        """
        jid, ok = self.get_jid(key, False)
        if ok:
            return jid
        return None

    def optional_jid_or_empty(self, key: str) -> 'JID':
        """
        OptionalJIDOrEmpty returns the JID under the given key. If there's no valid JID under the given key, this will return an empty JID.
        However, if the attribute is completely missing, this will not store an error.
        """
        jid, ok = self.get_jid(key, False)
        if ok:
            return jid
        return JID()

    def jid(self, key: str) -> 'JID':
        """
        JID returns the JID under the given key.
        If there's no valid JID under the given key, an error will be stored and a blank JID struct will be returned.
        """
        jid, _ = self.get_jid(key, True)
        return jid

    def get_string(self, key: str, require: bool) -> Tuple[str, bool]:
        """Get string attribute with error handling."""
        if key not in self.attrs:
            if require:
                self.errors.append(ValueError(f"didn't find required attribute '{key}'"))
            return "", False

        val = self.attrs[key]
        if isinstance(val, str):
            return val, True

        self.errors.append(TypeError(f"expected attribute '{key}' to be string, but was {type(val).__name__}"))
        return "", False

    def get_int64(self, key: str, require: bool) -> Tuple[int, bool]:
        """Get int64 attribute with error handling."""
        str_val, ok = self.get_string(key, require)
        if not ok:
            return 0, False

        try:
            int_val = int(str_val)
            return int_val, True
        except ValueError as e:
            self.errors.append(ValueError(f"failed to parse int in attribute '{key}': {e}"))
            return 0, False

    def get_uint64(self, key: str, require: bool) -> Tuple[int, bool]:
        """Get uint64 attribute with error handling."""
        str_val, ok = self.get_string(key, require)
        if not ok:
            return 0, False

        try:
            int_val = int(str_val)
            if int_val < 0:
                self.errors.append(ValueError(f"failed to parse uint in attribute '{key}': negative value"))
                return 0, False
            return int_val, True
        except ValueError as e:
            self.errors.append(ValueError(f"failed to parse uint in attribute '{key}': {e}"))
            return 0, False

    def get_bool(self, key: str, require: bool) -> Tuple[bool, bool]:
        """Get bool attribute with error handling."""
        str_val, ok = self.get_string(key, require)
        if not ok:
            return False, False

        # Parse bool similar to Go's strconv.ParseBool
        if str_val.lower() in ('1', 'true', 't'):
            return True, True
        elif str_val.lower() in ('0', 'false', 'f'):
            return False, True
        else:
            self.errors.append(ValueError(f"failed to parse bool in attribute '{key}': invalid syntax"))
            return False, False

    def get_unix_time(self, key: str, require: bool) -> Tuple[datetime, bool]:
        """Get unix timestamp attribute as datetime with error handling."""
        int_val, ok = self.get_int64(key, require)
        if not ok:
            return datetime.fromtimestamp(0), False
        elif int_val == 0:
            return datetime.fromtimestamp(0), True
        else:
            return datetime.fromtimestamp(int_val), True

    def get_unix_milli(self, key: str, require: bool) -> Tuple[datetime, bool]:
        """Get unix millisecond timestamp attribute as datetime with error handling."""
        int_val, ok = self.get_int64(key, require)
        if not ok:
            return datetime.fromtimestamp(0), False
        elif int_val == 0:
            return datetime.fromtimestamp(0), True
        else:
            return datetime.fromtimestamp(int_val / 1000), True

    def optional_string(self, key: str) -> str:
        """OptionalString returns the string under the given key."""
        str_val, _ = self.get_string(key, False)
        return str_val

    def string(self, key: str) -> str:
        """
        String returns the string under the given key.
        If there's no valid string under the given key, an error will be stored and an empty string will be returned.
        """
        str_val, _ = self.get_string(key, True)
        return str_val

    def optional_int(self, key: str) -> int:
        """OptionalInt returns the int under the given key or 0 if not found."""
        val, _ = self.get_int64(key, False)
        return val

    def int64(self, key: str) -> int:
        """Int64 returns the int64 under the given key."""
        val, _ = self.get_int64(key, True)
        return val

    def uint64(self, key: str) -> int:
        """Uint64 returns the uint64 under the given key."""
        val, _ = self.get_uint64(key, True)
        return val

    def optional_bool(self, key: str) -> bool:
        """OptionalBool returns the bool under the given key or False if not found."""
        val, _ = self.get_bool(key, False)
        return val

    def optional_unix_time(self, key: str) -> datetime:
        """OptionalUnixTime returns the unix timestamp under the given key as datetime."""
        val, _ = self.get_unix_time(key, False)
        return val

    def unix_time(self, key: str) -> datetime:
        """UnixTime returns the unix timestamp under the given key as datetime."""
        val, _ = self.get_unix_time(key, True)
        return val

    def optional_unix_milli(self, key: str) -> datetime:
        """OptionalUnixMilli returns the unix millisecond timestamp under the given key as datetime."""
        val, _ = self.get_unix_milli(key, False)
        return val

    def unix_milli(self, key: str) -> datetime:
        """UnixMilli returns the unix millisecond timestamp under the given key as datetime."""
        val, _ = self.get_unix_milli(key, True)
        return val

    def ok(self) -> bool:
        """OK returns true if there are no errors."""
        return len(self.errors) == 0

    def error(self) -> Optional[Exception]:
        """Error returns the list of errors as a single error interface, or None if there are no errors."""
        if self.ok():
            return None
        return ErrorList(self.errors)

    def int(self, key: str) -> int:
        """Int returns the int under the given key."""
        val, _ = self.get_int64(key, True)
        return val

    def bool(self, key: str) -> bool:
        """Bool returns the bool under the given key."""
        val, _ = self.get_bool(key, True)
        return val


class ErrorList(Exception):
    """ErrorList is a list of errors that implements the error interface itself."""

    def __init__(self, errors: List[Exception]):
        self.errors = errors
        super().__init__(str(errors))

    def __str__(self) -> str:
        """Error returns all the errors in the list as a string."""
        return str(self.errors)


# This would be added to the Node class in node.py:
def attr_getter(node: Node) -> AttrUtility:
    """AttrGetter returns the AttrUtility for this Node."""
    return AttrUtility(node.attrs)
