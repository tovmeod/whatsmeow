"""
Binary unpacking functionality for the WhatsApp protocol.

This module provides functions for unpacking binary data from the WhatsApp web API.
"""

import zlib
import io


def unpack(data: bytes) -> bytes:
    """
    Unpack the given decrypted data from the WhatsApp web API.

    It checks the first byte to decide whether to uncompress the data with zlib or just return as-is
    (without the first byte). There's currently no corresponding pack function because the equivalent
    of Marshal already returns the data with a leading zero (i.e. not compressed).

    Args:
        data: The encrypted data to unpack

    Returns:
        The unpacked data

    Raises:
        ValueError: If the data is compressed but cannot be decompressed
    """
    if not data:
        return b""

    data_type, data = data[0], data[1:]
    if 2 & data_type > 0:
        try:
            decompressor = zlib.decompressobj()
            data = decompressor.decompress(data)
        except zlib.error as e:
            raise ValueError(f"Failed to decompress data: {e}") from e

    return data
