"""
Binary encoder for WhatsApp protocol.

Port of whatsmeow/binary/encoder.go
"""
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Union, Callable

from ..datatypes.jid import (
    DEFAULT_USER_SERVER,
    HIDDEN_USER_SERVER,
    HOSTED_SERVER,
    INTEROP_SERVER,
    JID,
    MESSENGER_SERVER,
)
from .errors import InvalidTypeError
from .node import Node
from .token import (
    AD_JID,
    BINARY_8,
    BINARY_20,
    BINARY_32,
    DICTIONARY_0,
    FB_JID,
    HEX_8,
    INTEROP_JID,
    JID_PAIR,
    LIST_8,
    LIST_16,
    LIST_EMPTY,
    NIBBLE_8,
    PACKED_MAX,
)

# Size of a tag in the WhatsApp protocol
TAG_SIZE = 1


@dataclass
class BinaryEncoder:
    """Binary encoder for WhatsApp protocol."""
    data: bytearray = field(default_factory=bytearray)

    def get_data(self) -> bytearray:
        """Get the encoded data."""
        return self.data

    def push_byte(self, b: int) -> None:
        """Push a single byte to the data."""
        self.data.append(b)

    def push_bytes(self, bytes_data: bytes) -> None:
        """Push multiple bytes to the data."""
        self.data.extend(bytes_data)

    def push_int_n(self, value: int, n: int, little_endian: bool = False) -> None:
        """Push n bytes of an integer to the data."""
        for i in range(n):
            if little_endian:
                cur_shift = i
            else:
                cur_shift = n - i - 1
            self.push_byte((value >> (cur_shift * 8)) & 0xFF)

    def push_int20(self, value: int) -> None:
        """Push a 20-bit integer to the data."""
        self.push_bytes(bytes([
            (value >> 16) & 0x0F,
            (value >> 8) & 0xFF,
            value & 0xFF
        ]))

    def push_int8(self, value: int) -> None:
        """Push an 8-bit integer to the data."""
        self.push_int_n(value, 1)

    def push_int16(self, value: int) -> None:
        """Push a 16-bit integer to the data."""
        self.push_int_n(value, 2)

    def push_int32(self, value: int) -> None:
        """Push a 32-bit integer to the data."""
        self.push_int_n(value, 4)

    def push_string(self, value: str) -> None:
        """Push a string to the data."""
        self.push_bytes(value.encode('utf-8'))

    def write_byte_length(self, length: int) -> None:
        """Write the length of a byte array with the appropriate token."""
        if length < 256:
            self.push_byte(BINARY_8)
            self.push_int8(length)
        elif length < (1 << 20):
            self.push_byte(BINARY_20)
            self.push_int20(length)
        elif length < 0x7FFFFFFF:  # max int32
            self.push_byte(BINARY_32)
            self.push_int32(length)
        else:
            raise ValueError(f"length is too large: {length}")

    def write_node(self, n: Node) -> None:
        """Write a node to the data."""
        if n.tag == "0":
            self.push_byte(LIST_8)
            self.push_byte(LIST_EMPTY)
            return

        has_content = 1 if n.content is not None else 0
        self.write_list_start(2 * self.count_attributes(n.attrs) + TAG_SIZE + has_content)
        self.write_string(n.tag)
        self.write_attributes(n.attrs)
        if n.content is not None:
            self.write(n.content)

    def write(self, data: Any) -> None:
        """Write any data to the encoder."""
        if data is None:
            self.push_byte(LIST_EMPTY)
        elif isinstance(data, JID):
            self.write_jid(data)
        elif isinstance(data, str):
            self.write_string(data)
        elif isinstance(data, bool):
            self.write_string(str(data).lower())
        elif isinstance(data, int):
            self.write_string(str(data))
        elif isinstance(data, (bytes, bytearray)):
            self.write_bytes(data)
        elif isinstance(data, list) and all(isinstance(item, Node) for item in data):
            self.write_list_start(len(data))
            for n in data:
                self.write_node(n)
        else:
            raise InvalidTypeError(f"Unsupported type: {type(data)}")

    def write_string(self, data: str) -> None:
        """Write a string to the data."""
        from . import token

        token_index, found = token.index_of_single_token(data)
        if found:
            self.push_byte(token_index)
            return

        dict_index, token_index, found = token.index_of_double_byte_token(data)
        if found:
            self.push_byte(DICTIONARY_0 + dict_index)
            self.push_byte(token_index)
            return

        if validate_nibble(data):
            self.write_packed_bytes(data, NIBBLE_8)
            return

        if validate_hex(data):
            self.write_packed_bytes(data, HEX_8)
            return

        self.write_string_raw(data)

    def write_bytes(self, value: Union[bytes, bytearray]) -> None:
        """Write bytes to the data."""
        self.write_byte_length(len(value))
        self.push_bytes(value)

    def write_string_raw(self, value: str) -> None:
        """Write a raw string to the data."""
        self.write_byte_length(len(value))
        self.push_string(value)

    def write_jid(self, jid: JID) -> None:
        """Write a JID to the data."""
        if ((jid.server == DEFAULT_USER_SERVER and jid.device > 0) or
                jid.server == HIDDEN_USER_SERVER or
                jid.server == HOSTED_SERVER):
            self.push_byte(AD_JID)
            self.push_byte(jid.actual_agent())
            self.push_byte(jid.device)
            self.write_string(jid.user)
        elif jid.server == MESSENGER_SERVER:
            self.push_byte(FB_JID)
            self.write(jid.user)
            self.push_int16(jid.device)
            self.write(jid.server)
        elif jid.server == INTEROP_SERVER:
            self.push_byte(INTEROP_JID)
            self.write(jid.user)
            self.push_int16(jid.device)
            self.push_int16(jid.integrator)
            self.write(jid.server)
        else:
            self.push_byte(JID_PAIR)
            if not jid.user:
                self.push_byte(LIST_EMPTY)
            else:
                self.write(jid.user)
            self.write(jid.server)

    def write_attributes(self, attributes: Dict[str, Any]) -> None:
        """Write attributes to the data."""
        for key, val in attributes.items():
            if val == "" or val is None:
                continue
            self.write_string(key)
            self.write(val)

    def count_attributes(self, attributes: Dict[str, Any]) -> int:
        """Count the number of attributes."""
        count = 0
        for val in attributes.values():
            if val != "" and val is not None:
                count += 1
        return count

    def write_list_start(self, list_size: int) -> None:
        """Write the start of a list with the appropriate token."""
        if list_size == 0:
            self.push_byte(LIST_EMPTY)
        elif list_size < 256:
            self.push_byte(LIST_8)
            self.push_int8(list_size)
        else:
            self.push_byte(LIST_16)
            self.push_int16(list_size)

    def write_packed_bytes(self, value: str, data_type: int) -> None:
        """Write packed bytes to the data."""
        if len(value) > PACKED_MAX:
            raise ValueError(f"too many bytes to pack: {len(value)}")

        self.push_byte(data_type)

        rounded_length = math.ceil(len(value) / 2.0)
        if len(value) % 2 != 0:
            rounded_length |= 128
        self.push_byte(int(rounded_length))

        if data_type == NIBBLE_8:
            packer = pack_nibble
        elif data_type == HEX_8:
            packer = pack_hex
        else:
            raise ValueError(f"invalid packed byte data type {data_type}")

        for i in range(len(value) // 2):
            self.push_byte(self.pack_byte_pair(packer, ord(value[2*i]), ord(value[2*i+1])))

        if len(value) % 2 != 0:
            self.push_byte(self.pack_byte_pair(packer, ord(value[-1]), 0))

    def pack_byte_pair(self, packer: Callable[[int], int], part1: int, part2: int) -> int:
        """Pack two bytes into one."""
        return (packer(part1) << 4) | packer(part2)


def new_encoder() -> BinaryEncoder:
    """Create a new binary encoder."""
    return BinaryEncoder()


def validate_nibble(value: str) -> bool:
    """Validate if a string can be packed as nibbles (0-9, -, .)."""
    if len(value) > PACKED_MAX:
        return False
    for char in value:
        if not ('0' <= char <= '9') and char != '-' and char != '.':
            return False
    return True


def pack_nibble(value: int) -> int:
    """Pack a nibble value."""
    if value == ord('-'):
        return 10
    elif value == ord('.'):
        return 11
    elif value == 0:
        return 15
    elif ord('0') <= value <= ord('9'):
        return value - ord('0')
    else:
        raise ValueError(f"invalid string to pack as nibble: {value} / '{chr(value)}'")


def validate_hex(value: str) -> bool:
    """Validate if a string can be packed as hex (0-9, A-F)."""
    if len(value) > PACKED_MAX:
        return False
    for char in value:
        if not ('0' <= char <= '9') and not ('A' <= char <= 'F'):
            return False
    return True


def pack_hex(value: int) -> int:
    """Pack a hex value."""
    if ord('0') <= value <= ord('9'):
        return value - ord('0')
    elif ord('A') <= value <= ord('F'):
        return 10 + value - ord('A')
    elif value == 0:
        return 15
    else:
        raise ValueError(f"invalid string to pack as hex: {value} / '{chr(value)}'")
