"""
Decoder for WhatsApp binary protocol.

Port of whatsmeow/binary/decoder.go
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from ..exceptions import PymeowError
from ..datatypes.jid import INTEROP_SERVER, JID, MESSENGER_SERVER
from . import token
from .errors import InvalidJIDTypeError, InvalidNodeError, InvalidTokenError, InvalidTypeError, NonStringKeyError
from .node import Node


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

    def check_eos(self, length: int) -> None:
        """
        Check if reading the specified length would go beyond the end of the data.

        Args:
            length: The number of bytes to check

        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        if self.index + length > len(self.data):
            raise EOFError("unexpected end of data")

    def read_byte(self) -> int:
        """
        Read a single byte from the data.

        Returns:
            A tuple containing the byte read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        self.check_eos(1)
        b = self.data[self.index]
        self.index += 1
        return b

    def read_int_n(self, n: int, little_endian: bool) -> int:
        """
        Read an n-byte integer from the data.

        Args:
            n: The number of bytes to read
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        self.check_eos(n)
        ret = 0
        for i in range(n):
            if little_endian:
                cur_shift = i
            else:
                cur_shift = n - i - 1
            ret |= self.data[self.index + i] << (cur_shift * 8)

        self.index += n
        return ret

    def read_int8(self, little_endian: bool) -> int:
        """
        Read a 1-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        return self.read_int_n(1, little_endian)

    def read_int16(self, little_endian: bool) -> int:
        """
        Read a 2-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        return self.read_int_n(2, little_endian)

    def read_int20(self) -> int:
        """
        Read a 3-byte integer from the data, where only the lower 20 bits are used.

        Returns:
            A tuple containing the integer read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        self.check_eos(3)
        ret = ((self.data[self.index] & 15) << 16) + (self.data[self.index + 1] << 8) + self.data[self.index + 2]
        self.index += 3
        return ret

    def read_int32(self, little_endian: bool) -> int:
        """
        Read a 4-byte integer from the data.

        Args:
            little_endian: Whether the integer is in little-endian format

        Returns:
            A tuple containing the integer read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        return self.read_int_n(4, little_endian)

    def read_packed8(self, tag: int) -> str:
        """
        Read a packed string from the data.

        Args:
            tag: The tag indicating the packing format

        Returns:
            A tuple containing the string read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        start_byte = self.read_byte()
        result = []

        for i in range(start_byte & 127):
            try:
                curr_byte = self.read_byte()
            except EOFError as e:
                return ""

            lower = unpack_byte(tag, (curr_byte & 0xF0) >> 4)
            upper = unpack_byte(tag, curr_byte & 0x0F)
            result.append(chr(lower))
            result.append(chr(upper))

        ret = "".join(result)
        if (start_byte >> 7) != 0:
            ret = ret[:-1]
        return ret

    def read_list_size(self, tag: int) -> int:
        """
        Read the size of a list from the data.

        Args:
            tag: The tag indicating the list format

        Returns:
            A tuple containing the list size and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidTokenError: If the tag is invalid
        """
        if tag == token.LIST_EMPTY:
            return 0
        elif tag == token.LIST_8:
            return self.read_int8(False)
        elif tag == token.LIST_16:
            return self.read_int16(False)
        else:
            raise InvalidTokenError(f"readListSize with unknown tag {tag} at position {self.index}")

    def read(self, as_string: bool) -> None | List[Node] | bytes | str | JID:
        """
        Read a value from the data.

        Args:
            as_string: Whether to return binary data as a string

        Returns:
            A tuple containing the value read and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidTokenError:
        """
        tag_byte = self.read_byte()
        tag = tag_byte

        if tag == token.LIST_EMPTY:
            return None
        elif tag in (token.LIST_8, token.LIST_16):
            return self.read_list(tag)
        elif tag == token.BINARY_8:
            size = self.read_int8(False)
            return self.read_bytes_or_string(size, as_string)
        elif tag == token.BINARY_20:
            size = self.read_int20()
            return self.read_bytes_or_string(size, as_string)
        elif tag == token.BINARY_32:
            size = self.read_int32(False)
            return self.read_bytes_or_string(size, as_string)
        elif token.DICTIONARY_0 <= tag <= token.DICTIONARY_3:
            i = self.read_int8(False)
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
                return token.SINGLE_BYTE_TOKENS[tag]
            raise InvalidTokenError(f"{tag} at position {self.index}")

    def read_jid_pair(self) -> JID:
        """
        Read a JID pair from the data.

        Returns:
            A tuple containing the JID and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidJIDTypeError: If the JID type is invalid
        """
        user = self.read(True)

        server = self.read(True)
        if server is None:
            raise InvalidJIDTypeError()
        elif user is None:
            assert isinstance(server, str)
            return JID.new_jid("", server)

        assert isinstance(user, str)
        assert isinstance(server, str)
        return JID.new_jid(user, server)

    def read_interop_jid(self) -> JID:
        """
        Read an interop JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidJIDTypeError: If the JID type is invalid
        """
        user = self.read(True)
        device = self.read_int16(False)
        integrator = self.read_int16(False)
        server = self.read(True)
        if server != INTEROP_SERVER:
            raise InvalidJIDTypeError(f"expected {INTEROP_SERVER!r}, got {server!r}")

        assert isinstance(user, str)
        return JID(
            user=user,
            device=device,
            integrator=integrator,
            server=INTEROP_SERVER
        )

    def read_fb_jid(self) -> JID:
        """
        Read a Facebook JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidJIDTypeError: If the JID type is invalid
        """
        user = self.read(True)
        device= self.read_int16(False)
        server = self.read(True)
        if server != MESSENGER_SERVER:
            raise InvalidJIDTypeError(f"expected {MESSENGER_SERVER!r}, got {server!r}")

        assert isinstance(user, str)
        assert isinstance(server, str)
        return JID(
            user=user,
            device=device,
            server=server
        )

    def read_ad_jid(self) -> JID:
        """
        Read an AD JID from the data.

        Returns:
            A tuple containing the JID and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        agent = self.read_byte()
        device = self.read_byte()
        user = self.read(True)
        assert isinstance(user, str)
        return JID.new_ad_jid(user, agent, device)

    def read_attributes(self, n: int) -> Dict[str, Any]:
        """
        Read attributes from the data.

        Args:
            n: The number of attributes to read

        Returns:
            A tuple containing the attributes and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            NonStringKeyError: If a key is not a string
        """
        if n == 0:
            return {}
        ret = {}
        for i in range(n):
            key_ifc = self.read(True)
            if not isinstance(key_ifc, str):
                raise NonStringKeyError(f"at position {self.index} ({type(key_ifc)}): {key_ifc!r}")
            key = key_ifc
            ret[key] = self.read(True)
        return ret

    def read_list(self, tag: int) -> List[Node]:
        """
        Read a list of nodes from the data.

        Args:
            tag: The tag indicating the list format

        Returns:
            A tuple containing the list of nodes and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidTokenError
        """
        size = self.read_list_size(tag)
        ret = []
        for i in range(size):
            n = self.read_node()
            ret.append(n)
        return ret

    def read_node(self) -> Node:
        """
        Read a node from the data.

        Returns:
            A tuple containing the node and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
            InvalidNodeError
        """
        size = self.read_int8(False)
        list_size = self.read_list_size(size)
        raw_desc = self.read(True)
        # Ensure tag is a string
        if not isinstance(raw_desc, str):
            raise InvalidNodeError(f"Expected string tag, got {type(raw_desc)}")
        tag = raw_desc
        if list_size == 0 or not tag:
            raise InvalidNodeError()

        attrs = self.read_attributes((list_size - 1) >> 1)
        if list_size % 2 == 1:
            return Node(tag=tag, attrs=attrs)
        raw_content = self.read(False)
        content: Optional[Union[List[Node], bytes]] = None

        if raw_content is not None:
            if isinstance(raw_content, (bytes, list)):
                # For list, we need to ensure it's a list of Nodes
                if isinstance(raw_content, list):
                    # Validate that all items in the list are Node objects
                    if all(isinstance(item, Node) for item in raw_content):
                        content = raw_content
                    else:
                        raise InvalidNodeError("List content must contain only Node objects")
                else:
                    content = raw_content
            else:
                # If it's not bytes or list, it shouldn't be used as content
                # The Go implementation would handle this differently, but for safety we'll convert
                if isinstance(raw_content, str):
                    content = raw_content.encode('utf-8')
                else:
                    raise InvalidNodeError(f"Invalid content type: {type(raw_content)}")

        return Node(tag=tag, attrs=attrs, content=content)

    def read_bytes_or_string(self, length: int, as_string: bool) -> bytes | str:
        """
        Read bytes or a string from the data.

        Args:
            length: The number of bytes to read
            as_string: Whether to return the data as a string

        Returns:
            A tuple containing the data and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        data = self.read_raw(length)
        if as_string:
            return data.decode('utf-8', errors='replace')
        return data

    def read_raw(self, length: int) -> bytes:
        """
        Read raw bytes from the data.

        Args:
            length: The number of bytes to read

        Returns:
            A tuple containing the bytes and an optional error
        Raises:
            EOFError: If reading would go beyond the end of the data
        """
        self.check_eos(length)
        ret = self.data[self.index:self.index + length]
        self.index += length
        return ret


def unpack_byte(tag: int, value: int) -> int:
    """
    Unpack a byte based on the tag.

    Args:
        tag: The tag indicating the unpacking format
        value: The value to unpack

    Returns:
        A tuple containing the unpacked byte and an optional error
    Raises:
        InvalidTypeError: If the tag is invalid
    """
    if tag == token.NIBBLE_8:
        return unpack_nibble(value)
    elif tag == token.HEX_8:
        return unpack_hex(value)
    else:
        raise InvalidTypeError(f"unpackByte with unknown tag {tag}")


def unpack_nibble(value: int) -> int:
    """
    Unpack a nibble.

    Args:
        value: The value to unpack

    Returns:
        A tuple containing the unpacked nibble and an optional error
    Raises:
        InvalidTypeError: If the value is invalid
    """
    if value < 10:
        return ord('0') + value
    elif value == 10:
        return ord('-')
    elif value == 11:
        return ord('.')
    elif value == 15:
        return 0
    else:
        raise InvalidTypeError(f"unpackNibble with value {value}")


def unpack_hex(value: int) -> int:
    """
    Unpack a hex value.

    Args:
        value: The value to unpack

    Returns:
        A tuple containing the unpacked hex value and an optional error
    Raises:
        InvalidTypeError:
    """
    if value < 10:
        return ord('0') + value
    elif value < 16:
        return ord('A') + value - 10
    else:
        raise InvalidTypeError(f"unpackHex with value {value}")

class DecodingError(PymeowError):
    """Error that occurs during binary decoding operations."""
    pass

def unmarshal(data: bytes) -> Node:
    """
    Unmarshal binary data into a Node.

    Args:
        data: The binary data to unmarshal

    Returns:
        A tuple containing the Node and an optional error
    Raises:
        DecodingError: if r.index != len(r.data): leftover bytes after decoding
    """
    r = BinaryDecoder.new_decoder(data)
    n = r.read_node()
    if r.index != len(r.data):
        raise DecodingError(f"{len(r.data) - r.index} leftover bytes after decoding")
    return n
