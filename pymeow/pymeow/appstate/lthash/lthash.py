"""
LTHash implementation for WhatsApp app state.

Port of whatsmeow/appstate/lthash/lthash.go
"""
import struct
from dataclasses import dataclass
from typing import List

from ...util.hkdfutil import expand_hmac


@dataclass
class LTHash:
    """
    LTHash implements a summation based hash algorithm that maintains the
    integrity of a piece of data over a series of mutations. You can add/remove
    mutations, and it'll return a hash equal to if the same series of mutations
    was made sequentially.
    """
    hkdf_info: bytes
    hkdf_size: int

    def subtract_then_add(self, base: bytes, subtract: List[bytes], add: List[bytes]) -> bytes:
        """
        Subtract then add mutations to a base hash.

        Args:
            base: The base hash
            subtract: The mutations to subtract
            add: The mutations to add

        Returns:
            The new hash
        """
        output = bytearray(base)
        self.subtract_then_add_in_place(output, subtract, add)
        return bytes(output)

    def subtract_then_add_in_place(self, base: bytearray, subtract: List[bytes], add: List[bytes]) -> None:
        """
        Subtract then add mutations to a base hash in place.

        Args:
            base: The base hash
            subtract: The mutations to subtract
            add: The mutations to add
        """
        self._multiple_op(base, subtract, True)
        self._multiple_op(base, add, False)

    def _multiple_op(self, base: bytearray, input_data: List[bytes], subtract: bool) -> None:
        """
        Apply multiple operations to a base hash.

        Args:
            base: The base hash
            input_data: The input data
            subtract: Whether to subtract or add
        """
        for item in input_data:
            hashed = expand_hmac(item, self.hkdf_info, self.hkdf_size)
            _perform_pointwise_with_overflow(base, hashed, subtract)


def _perform_pointwise_with_overflow(base: bytearray, input_data: bytes, subtract: bool) -> bytes:
    """
    Perform pointwise addition or subtraction with overflow.

    Args:
        base: The base hash
        input_data: The input data
        subtract: Whether to subtract or add

    Returns:
        The modified base hash
    """
    for i in range(0, len(base), 2):
        x = struct.unpack("<H", base[i:i+2])[0]
        y = struct.unpack("<H", input_data[i:i+2])[0]

        if subtract:
            result = (x - y) & 0xFFFF  # Ensure result is 16-bit
        else:
            result = (x + y) & 0xFFFF  # Ensure result is 16-bit

        base[i:i+2] = struct.pack("<H", result)

    return base


# WAPatchIntegrity is a LTHash instance initialized with the details used for verifying integrity of WhatsApp app state sync patches.
WAPatchIntegrity = LTHash(b"WhatsApp Patch Integrity", 128)
