"""
Tests for the binary encoder implementation.

These tests verify that the binary encoder correctly serializes
Python objects into WhatsApp's binary protocol format.
"""

import pytest

from py.pymeow.binary.encoder import BinaryEncoder, marshal_and_pack, new_encoder, pack
from py.pymeow.binary.node import Node
from py.pymeow.binary.token import DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS
from py.pymeow.datatypes.jid import JID


def test_encoder_initialization():
    """Test that the encoder initializes with the expected state."""
    encoder = new_encoder()
    assert encoder.data == bytearray([0]), "Encoder should initialize with a single zero byte"


def test_push_byte():
    """Test pushing a single byte to the encoder."""
    encoder = new_encoder()
    encoder.push_byte(42)
    assert encoder.data == bytearray([0, 42]), "Encoder should append the byte correctly"


def test_push_bytes():
    """Test pushing multiple bytes to the encoder."""
    encoder = new_encoder()
    encoder.push_bytes(b'hello')
    assert encoder.data == bytearray([0]) + b'hello', "Encoder should append the bytes correctly"


def test_push_int_operations():
    """Test pushing integers of different sizes to the encoder."""
    encoder = new_encoder()

    # Test 8-bit integer
    encoder.push_int8(42)
    assert encoder.data[-1] == 42, "8-bit integer should be encoded correctly"

    # Test 16-bit integer
    encoder.push_int16(1000)
    assert encoder.data[-2:] == bytearray([3, 232]), "16-bit integer should be encoded correctly"

    # Test 32-bit integer
    encoder.push_int32(16777216)  # 2^24
    assert encoder.data[-4:] == bytearray([1, 0, 0, 0]), "32-bit integer should be encoded correctly"


def test_write_string_with_token():
    """Test writing a string that exists in the token dictionary."""
    encoder = new_encoder()

    # Test with a single-byte token
    if len(SINGLE_BYTE_TOKENS) > 1:
        test_token = SINGLE_BYTE_TOKENS[1]  # Use the first non-empty token
        start_len = len(encoder.data)
        encoder.write_string(test_token)
        assert len(encoder.data) == start_len + 1, "Single-byte token should add exactly one byte"

    # Test with a double-byte token if available
    if DOUBLE_BYTE_TOKENS and DOUBLE_BYTE_TOKENS[0]:
        test_token = DOUBLE_BYTE_TOKENS[0][0]  # Use the first token from first dictionary
        start_len = len(encoder.data)
        encoder.write_string(test_token)
        assert len(encoder.data) == start_len + 2, "Double-byte token should add exactly two bytes"


def test_write_string_raw():
    """Test writing a raw string that's not in the token dictionary."""
    encoder = new_encoder()
    test_string = "This is a test string not in any token dictionary"
    start_len = len(encoder.data)
    encoder.write_string(test_string)
    # Length should be: original + 1 (for binary marker) + 1 (for length) + len(string)
    expected_len = start_len + 2 + len(test_string)
    assert len(encoder.data) == expected_len, "Raw string should be encoded with correct length"


def test_write_jid():
    """Test writing different types of JIDs."""
    encoder = new_encoder()

    # Test standard JID
    jid = JID(user="test", server="s.whatsapp.net")
    start_len = len(encoder.data)
    encoder.write_jid(jid)
    assert len(encoder.data) > start_len, "JID should be encoded successfully"

    # Test JID with device
    jid_with_device = JID(user="test", server="s.whatsapp.net", device=1)
    start_len = len(encoder.data)
    encoder.write_jid(jid_with_device)
    assert len(encoder.data) > start_len, "JID with device should be encoded successfully"


def test_write_node():
    """Test writing a complete node."""
    # Create a simple node
    node = Node(
        tag="message",
        attributes={"id": "123", "to": "recipient@s.whatsapp.net"},
        content="Hello, world!"
    )

    encoder = new_encoder()
    start_len = len(encoder.data)
    encoder.write_node(node)
    assert len(encoder.data) > start_len, "Node should be encoded successfully"


def test_pack_function():
    """Test the pack function for small and large payloads."""
    # Small payload (should not be compressed)
    small_data = b'A' * 500
    packed_small = pack(small_data)
    assert packed_small[0] == 0, "Small payload should not be compressed"
    assert packed_small[1:] == small_data, "Small payload should be preserved exactly"

    # Large payload (may be compressed)
    large_data = b'B' * 5000
    packed_large = pack(large_data)
    assert packed_large[0] in (0, 2), "Large payload should be either uncompressed (0) or compressed (2)"

    # If compressed, length should be smaller
    if packed_large[0] == 2:
        assert len(packed_large) < len(large_data) + 1, "Compressed data should be smaller than original"


def test_marshal_and_pack():
    """Test the combined marshal and pack operation."""
    node = Node(
        tag="iq",
        attributes={"id": "test_id", "type": "get"},
        content=None
    )

    result = marshal_and_pack(node)
    assert isinstance(result, bytes), "Result should be bytes"
    assert len(result) > 1, "Result should have data after the flag byte"


def test_string_caching():
    """Test that string caching works correctly."""
    # Clear the cache first
    BinaryEncoder._string_cache = {}

    encoder = new_encoder()
    test_string = "test_cache_string"

    # First write should cache the string
    encoder.write_string(test_string)
    assert test_string in BinaryEncoder._string_cache, "String should be cached after first write"

    # Create a new encoder and write the same string
    encoder2 = new_encoder()
    start_len = len(encoder2.data)
    encoder2.write_string(test_string)
    # The cached encoding should be used
    assert len(encoder2.data) > start_len, "Cached string should be written successfully"


def test_complex_node_structure():
    """Test encoding a complex node structure with nested nodes."""
    # Create a complex node with nested children
    child1 = Node(tag="child1", attributes={"attr1": "value1"}, content=None)
    child2 = Node(tag="child2", attributes={"attr2": "value2"}, content="Child content")

    parent = Node(
        tag="parent",
        attributes={"id": "parent_id"},
        content=[child1, child2]
    )

    # Marshal the parent node
    result = parent.marshal()
    assert isinstance(result, bytes), "Result should be bytes"
    assert len(result) > 1, "Result should have data after the flag byte"

    # Try to unmarshal it back
    decoded, error = Node.unmarshal(result)
    assert error is None, "Should decode without errors"
    assert decoded.tag == "parent", "Decoded node should have the same tag"
    assert len(decoded.get_children()) == 2, "Decoded node should have two children"


if __name__ == "__main__":
    pytest.main(['-xvs', __file__])
