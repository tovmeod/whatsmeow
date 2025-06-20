"""Test binary unpacking functionality."""
import zlib

import pytest

from ..pymeow.binary.unpack import unpack


def test_unpack_empty():
    """Test unpacking empty data."""
    assert unpack(b"") == b""


def test_unpack_uncompressed():
    """Test unpacking uncompressed data."""
    # First byte 0 means uncompressed
    data = b"\x00Hello, World!"
    assert unpack(data) == b"Hello, World!"


def test_unpack_compressed():
    """Test unpacking compressed data."""
    # Create compressed data
    original = b"Hello, World! This is a test of compressed data."
    compressed = zlib.compress(original)

    # First byte 2 means compressed
    data = b"\x02" + compressed

    assert unpack(data) == original


def test_unpack_invalid_compressed():
    """Test unpacking invalid compressed data."""
    # First byte 2 means compressed, but data is not valid compressed data
    data = b"\x02Invalid compressed data"

    with pytest.raises(ValueError, match="Failed to decompress data"):
        unpack(data)


def test_unpack_other_flags():
    """Test unpacking with other flags in the first byte."""
    # First byte 1 means some other flag is set, but not compression
    data = b"\x01Hello, World!"
    assert unpack(data) == b"Hello, World!"

    # First byte 3 means compression flag (2) and some other flag (1) are set
    original = b"Hello, World! This is a test of compressed data."
    compressed = zlib.compress(original)
    data = b"\x03" + compressed

    assert unpack(data) == original
