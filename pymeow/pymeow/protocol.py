"""
PyMeow Protocol Module - WhatsApp Binary Protocol Implementation

This module handles the binary protocol used for encoding and decoding
WhatsApp Web messages using protocol buffer definitions.
"""
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Union, List
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import ProtocolError
from .generated import WAMsgTransport_pb2
from .generated.waCommon import WACommon_pb2
from .generated.waE2E import WAWebProtobufsE2E_pb2

logger = logging.getLogger(__name__)


@dataclass
class ProtocolNode:
    """A node in the WhatsApp protocol tree.
    
    This class represents a node in the XML-like protocol used by WhatsApp
    for message construction and processing.
    """
    tag: str
    attrs: Dict[str, str] = field(default_factory=dict)
    content: Any = None
    children: List['ProtocolNode'] = field(default_factory=list)
    
    def add_child(self, child: 'ProtocolNode') -> None:
        """Add a child node to this node."""
        if self.children is None:
            self.children = []
        self.children.append(child)
    
    def get_attribute(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get an attribute value by name."""
        return self.attrs.get(name, default)
    
    def set_attribute(self, name: str, value: str) -> None:
        """Set an attribute value."""
        self.attrs[name] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the node and its children to a dictionary."""
        result = {
            'tag': self.tag,
            'attrs': self.attrs.copy(),
        }
        
        if self.content is not None:
            result['content'] = self.content
            
        if self.children:
            result['children'] = [child.to_dict() for child in self.children]
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProtocolNode':
        """Create a ProtocolNode from a dictionary."""
        node = cls(
            tag=data['tag'],
            attrs=data.get('attrs', {}).copy(),
            content=data.get('content')
        )
        
        for child_data in data.get('children', []):
            node.add_child(cls.from_dict(child_data))
            
        return node

class BinaryMessageType(IntEnum):
    """Binary protocol message types for WhatsApp Web."""
    ENCODED_BYTES = 0x00
    ENCODED_STRING = 0x01
    DICTIONARY_0 = 0x02
    DICTIONARY_1 = 0x03
    DICTIONARY_2 = 0x04
    DICTIONARY_3 = 0x05
    ARRAY_0 = 0x06
    ARRAY_1 = 0x07
    ARRAY_2 = 0x08
    ARRAY_3 = 0x09
    TAGS = 0x0A
    PAIR_PLAIN = 0x0B
    PAIR_ENCRYPTED = 0x0C
    PAIR_ENCRYPTED_WITH_KEYS = 0x0D
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN = 0x0E
    PAIR_ENCRYPTED_WITH_KEYS_AND_ENCRYPTED = 0x0F
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED = 0x10
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_2 = 0x11
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_3 = 0x12
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_4 = 0x13
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_5 = 0x14
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_6 = 0x15
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_7 = 0x16
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_8 = 0x17
    PAIR_ENCRYPTED_WITH_KEYS_AND_PLAIN_AND_ENCRYPTED_9 = 0x18

class ProtocolEncoder:
    """Encodes protocol buffer messages into binary format for WhatsApp Web."""

    def __init__(self, enc_key: bytes = b"", mac_key: bytes = b""):
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.sequence_number = 0

    def encode_message(self, message: WAMsgTransport_pb2.MessageTransport) -> bytes:
        """
        Encode a protocol buffer message into binary format.

        Args:
            message: The protocol buffer message to encode

        Returns:
            Encoded binary data
        """
        transport = WAMsgTransport_pb2.MessageTransport()
        transport.payload.applicationPayload.CopyFrom(message)

        encoded = transport.SerializeToString()
        if self.enc_key:
            encoded = self._encrypt_payload(encoded)

        return self._encode_with_header(encoded)

    def _encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload using the session encryption key."""
        if not self.enc_key:
            return data

        aesgcm = AESGCM(self.enc_key)
        nonce = struct.pack(">Q", self.sequence_number) + b"\x00\x00\x00\x00"
        self.sequence_number += 1

        return aesgcm.encrypt(nonce, data, None)

    def _encode_with_header(self, data: bytes) -> bytes:
        """Add binary protocol header to encoded data."""
        header = struct.pack(">I", len(data))
        return header + data

class ProtocolDecoder:
    """Decodes binary format into protocol buffer messages."""

    def __init__(self, dec_key: bytes = b"", mac_key: bytes = b""):
        self.dec_key = dec_key
        self.mac_key = mac_key
        self.sequence_number = 0

    def decode_message(self, data: bytes) -> WAMsgTransport_pb2.MessageTransport:
        """
        Decode binary data into a protocol buffer message.

        Args:
            data: The binary data to decode

        Returns:
            Decoded protocol buffer message
        """
        if self.dec_key:
            data = self._decrypt_payload(data)

        transport = WAMsgTransport_pb2.MessageTransport()
        transport.ParseFromString(self._decode_with_header(data))

        return transport.payload.applicationPayload

    def _decrypt_payload(self, data: bytes) -> bytes:
        """Decrypt payload using the session decryption key."""
        if not self.dec_key:
            return data

        aesgcm = AESGCM(self.dec_key)
        nonce = struct.pack(">Q", self.sequence_number) + b"\x00\x00\x00\x00"
        self.sequence_number += 1

        return aesgcm.decrypt(nonce, data, None)

    def _decode_with_header(self, data: bytes) -> bytes:
        """Remove binary protocol header from encoded data."""
        header_size = struct.calcsize(">I")
        size = struct.unpack(">I", data[:header_size])[0]
        return data[header_size:header_size + size]
