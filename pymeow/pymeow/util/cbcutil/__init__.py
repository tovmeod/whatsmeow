"""
CBC utility functions for AES-256-CBC encryption and decryption.

Port of util/cbcutil/cbc.go
"""

from .cbc import (
    File,
    decrypt,
    decrypt_file,
    encrypt,
    encrypt_stream,
)

__all__ = [
    "File",
    "decrypt",
    "decrypt_file",
    "encrypt",
    "encrypt_stream",
]
