"""
Decoder for WhatsApp binary protocol.

Port of whatsmeow/binary/decoder.go
"""
import io
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from ..types.jid import JID, DEFAULT_USER_SERVER, MESSENGER_SERVER, INTEROP_SERVER
from .errors import (
    InvalidTypeError, InvalidJIDTypeError, InvalidNodeError,
    InvalidTokenError, NonStringKeyError
)
from .node import Node
from . import token


@dataclass
class BinaryDecoder:
    """
    Decoder for WhatsApp binary protocol.

    This class handles decoding of WhatsApp's binary XML format into Node objects.
    """
    data: bytes
    index: int = 0

    @classmethod
    def new_decoder(cls, data: bytes) -> 'BinaryDecoder':
        """
        Create a new decoder instance.

        Args:
            data: The binary data to decode

        Returns:
            A new BinaryDecoder instance
        """
        return cls(data=data, index=0)

    def check_eos(self, length: int) -> Optional[Exception]:
        """
        Check if reading the specified length would go beyond the end of the data.

        Args:
            length: The number of bytes to check

        Returns:
            io.EOF if reading would go beyond the end of the data, None otherwise
        """
        if self.index + length > len(self.data):
            return io.EOF
        return None

    def read_byte(self) -> Tuple[int, Optional[Exception]]:
        """
        Read a single byte from the data.

        Returns:
            A tuple containing the byte read and an optional error
        """
        err = self.check_eos(1)
        if err:
            return 0, err

        b = self.data[self.index]
        self.index += 1

        return b, None

    def read_int_n(self, n: int, little_endian: bool) -> Tuple[int, Optional[Exception]]:
        """
        Read an n-byte integer from the data.

        Args:
            n: The number of bytes to read
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        """
        err = self.check_eos(n)
        if err:
            return 0, err

        ret = 0
        for i in range(n):
            if little_endian:
                cur_shift = i
            else:
                cur_shift = n - i - 1
            ret |= self.data[self.index + i] << (cur_shift * 8)

        self.index += n
        return ret, None

    def read_int8(self, little_endian: bool) -> Tuple[int, Optional[Exception]]:
        """
        Read a 1-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        """
        return self.read_int_n(1, little_endian)

    def read_int16(self, little_endian: bool) -> Tuple[int, Optional[Exception]]:
        """
        Read a 2-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        """
        return self.read_int_n(2, little_endian)

    def read_int20(self) -> Tuple[int, Optional[Exception]]:
        """
        Read a 3-byte integer from the data, where only the lower 20 bits are used.

        Returns:
            A tuple containing the integer read and an optional error
        """
        err = self.check_eos(3)
        if err:
            return 0, err

        ret = ((self.data[self.index] & 15) << 16) + (self.data[self.index + 1] << 8) + self.data[self.index + 2]
        self.index += 3
        return ret, None

    def read_int32(self, little_endian: bool) -> Tuple[int, Optional[Exception]]:
        """
        Read a 4-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        """
        return self.read_int_n(4, little_endian)

    def read_packed8(self, tag: int) -> Tuple[str, Optional[Exception]]:
        """
        Read a packed string from the data.

        Args:
            tag: The tag indicating the packing format

        Returns:
            A tuple containing the string read and an optional error
        """
        start_byte, err = self.read_byte()
        if err:
            return "", err

        result = []

        for i in range(start_byte & 127):
            curr_byte, err = self.read_byte()
            if err:
                return "", err

            lower, err = unpack_byte(tag, (curr_byte & 0xF0) >> 4)
            if err:
                return "", err

            upper, err = unpack_byte(tag, curr_byte & 0x0F)
            if err:
                return "", err

            result.append(chr(lower))
            result.append(chr(upper))

        ret = "".join(result)
        if (start_byte >> 7) != 0:
            ret = ret[:-1]
        return ret, None

    def read_list_size(self, tag: int) -> Tuple[int, Optional[Exception]]:
        """
        Read the size of a list from the data.

        Args:
            tag: The tag indicating the list format

        Returns:
            A tuple containing the list size and an optional error
        """
        if tag == token.LIST_EMPTY:
            return 0, None
        elif tag == token.LIST_8:
            return self.read_int8(False)
        elif tag == token.LIST_16:
            return self.read_int16(False)
        else:
            return 0, InvalidTokenError(f"readListSize with unknown tag {tag} at position {self.index}")

    def read(self, as_string: bool) -> Tuple[Any, Optional[Exception]]:
        """
        Read a value from the data.

        Args:
            as_string: Whether to return binary data as a string

        Returns:
            A tuple containing the value read and an optional error
        """
        tag_byte, err = self.read_byte()
        if err:
            return None, err

        tag = tag_byte

        if tag == token.LIST_EMPTY:
            return None, None
        elif tag in (token.LIST_8, token.LIST_16):
            return self.read_list(tag)
        elif tag == token.BINARY_8:
            size, err = self.read_int8(False)
            if err:
                return None, err
            return self.read_bytes_or_string(size, as_string)
        elif tag == token.BINARY_20:
            size, err = self.read_int20()
            if err:
                return None, err
            return self.read_bytes_or_string(size, as_string)
        elif tag == token.BINARY_32:
            size, err = self.read_int32(False)
            if err:
                return None, err
            return self.read_bytes_or_string(size, as_string)
        elif token.DICTIONARY_0 <= tag <= token.DICTIONARY_3:
            i, err = self.read_int8(False)
            if err:
                return "", err
            return token.get_double_token(tag - token.DICTIONARY_0, i)
        elif tag == token.FB_JID:
            return self.read_fb_jid()
        elif tag == token.INTEROP_JID:
            return self.read_interop_jid()
        elif tag == token.JID_PAIR:
            return self.read_jid_pair()
        elif tag == token.AD_JID:
            return self.read_ad_jid()
        elif tag in (token.NIBBLE_8, token.HEX_8):
            return self.read_packed8(tag)
        else:
            if 1 <= tag < len(token.SINGLE_BYTE_TOKENS):
                return token.SINGLE_BYTE_TOKENS[tag], None
            return "", InvalidTokenError(f"{tag} at position {self.index}")

    def read_jid_pair(self) -> Tuple[Any, Optional[Exception]]:
        """
        Read a JID pair from the data.

        Returns:
            A tuple containing the JID and an optional error
        """
        user, err = self.read(True)
        if err:
            return None, err

        server, err = self.read(True)
        if err:
            return None, err
        elif server is None:
            return None, InvalidJIDTypeError()
        elif user is None:
            return JID.new_jid("", server), None

        return JID.new_jid(user, server), None

    def read_interop_jid(self) -> Tuple[Any, Optional[Exception]]:
        """
        Read an interop JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        """
        user, err = self.read(True)
        if err:
            return None, err

        device, err = self.read_int16(False)
        if err:
            return None, err

        integrator, err = self.read_int16(False)
        if err:
            return None, err

        server, err = self.read(True)
        if err:
            return None, err
        elif server != INTEROP_SERVER:
            return None, InvalidJIDTypeError(f"expected {INTEROP_SERVER}, got {server}")

        return JID(
            user=user,
            device=device,
            integrator=integrator,
            server=INTEROP_SERVER
        ), None

    def read_fb_jid(self) -> Tuple[Any, Optional[Exception]]:
        """
        Read a Facebook JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        """
        user, err = self.read(True)
        if err:
            return None, err

        device, err = self.read_int16(False)
        if err:
            return None, err

        server, err = self.read(True)
        if err:
            return None, err
        elif server != MESSENGER_SERVER:
            return None, InvalidJIDTypeError(f"expected {MESSENGER_SERVER}, got {server}")

        return JID(
            user=user,
            device=device,
            server=server
        ), None

    def read_ad_jid(self) -> Tuple[Any, Optional[Exception]]:
        """
        Read an AD JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        """
        agent, err = self.read_byte()
        if err:
            return None, err

        device, err = self.read_byte()
        if err:
            return None, err

        user, err = self.read(True)
        if err:
            return None, err

        return JID.new_ad_jid(user, agent, device), None

    def read_attributes(self, n: int) -> Tuple[Dict[str, Any], Optional[Exception]]:
        """
        Read attributes from the data.

        Args:
            n: The number of attributes to read

        Returns:
            A tuple containing the attributes and an optional error
        """
        if n == 0:
            return None, None

        ret = {}
        for i in range(n):
            key_ifc, err = self.read(True)
            if err:
                return None, err

            if not isinstance(key_ifc, str):
                return None, NonStringKeyError(f"at position {self.index} ({type(key_ifc)}): {key_ifc}")

            key = key_ifc

            ret[key], err = self.read(True)
            if err:
                return None, err

        return ret, None

    def read_list(self, tag: int) -> Tuple[List[Node], Optional[Exception]]:
        """
        Read a list of nodes from the data.

        Args:
            tag: The tag indicating the list format

        Returns:
            A tuple containing the list of nodes and an optional error
        """
        size, err = self.read_list_size(tag)
        if err:
            return None, err

        ret = []
        for i in range(size):
            n, err = self.read_node()
            if err:
                return None, err

            ret.append(n)

        return ret, None

    def read_node(self) -> Tuple[Node, Optional[Exception]]:
        """
        Read a node from the data.

        Returns:
            A tuple containing the node and an optional error
        """
        size, err = self.read_int8(False)
        if err:
            return None, err

        list_size, err = self.read_list_size(size)
        if err:
            return None, err

        raw_desc, err = self.read(True)
        if err:
            return None, err

        tag = raw_desc
        if list_size == 0 or not tag:
            return None, InvalidNodeError()

        attrs, err = self.read_attributes((list_size - 1) >> 1)
        if err:
            return None, err

        if attrs is None:
            attrs = {}

        if list_size % 2 == 1:
            return Node(tag=tag, attributes=attrs), None

        content, err = self.read(False)
        if err:
            return None, err

        return Node(tag=tag, attributes=attrs, content=content), None

    def read_bytes_or_string(self, length: int, as_string: bool) -> Tuple[Any, Optional[Exception]]:
        """
        Read bytes or a string from the data.

        Args:
            length: The number of bytes to read
            as_string: Whether to return the data as a string

        Returns:
            A tuple containing the data and an optional error
        """
        data, err = self.read_raw(length)
        if err:
            return None, err

        if as_string:
            return data.decode('utf-8', errors='replace'), None
        return data, None

    def read_raw(self, length: int) -> Tuple[bytes, Optional[Exception]]:
        """
        Read raw bytes from the data.

        Args:
            length: The number of bytes to read

        Returns:
            A tuple containing the bytes and an optional error
        """
        err = self.check_eos(length)
        if err:
            return None, err

        ret = self.data[self.index:self.index + length]
        self.index += length

        return ret, None


def unpack_byte(tag: int, value: int) -> Tuple[int, Optional[Exception]]:
    """
    Unpack a byte based on the tag.

    Args:
        tag: The tag indicating the unpacking format
        value: The value to unpack

    Returns:
        A tuple containing the unpacked byte and an optional error
    """
    if tag == token.NIBBLE_8:
        return unpack_nibble(value)
    elif tag == token.HEX_8:
        return unpack_hex(value)
    else:
        return 0, InvalidTypeError(f"unpackByte with unknown tag {tag}")


def unpack_nibble(value: int) -> Tuple[int, Optional[Exception]]:
    """
    Unpack a nibble.

    Args:
        value: The value to unpack

    Returns:
        A tuple containing the unpacked nibble and an optional error
    """
    if value < 10:
        return ord('0') + value, None
    elif value == 10:
        return ord('-'), None
    elif value == 11:
        return ord('.'), None
    elif value == 15:
        return 0, None
    else:
        return 0, InvalidTypeError(f"unpackNibble with value {value}")


def unpack_hex(value: int) -> Tuple[int, Optional[Exception]]:
    """
    Unpack a hex value.

    Args:
        value: The value to unpack

    Returns:
        A tuple containing the unpacked hex value and an optional error
    """
    if value < 10:
        return ord('0') + value, None
    elif value < 16:
        return ord('A') + value - 10, None
    else:
        return 0, InvalidTypeError(f"unpackHex with value {value}")


def unmarshal(data: bytes) -> Tuple[Node, Optional[Exception]]:
    """
    Unmarshal binary data into a Node.

    Args:
        data: The binary data to unmarshal

    Returns:
        A tuple containing the Node and an optional error
    """
    r = BinaryDecoder.new_decoder(data)
    n, err = r.read_node()
    if err:
        return None, err
    elif r.index != len(r.data):
        return n, Exception(f"{len(r.data) - r.index} leftover bytes after decoding")
    return n, None
