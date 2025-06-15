"""
CBC describes a block cipher mode. In cryptography, a block cipher mode of operation is an algorithm that uses a
block cipher to provide an information service such as confidentiality or authenticity. A block cipher by itself
is only suitable for the secure cryptographic transformation (encryption or decryption) of one fixed-length group of
bits called a block. A mode of operation describes how to repeatedly apply a cipher's single-block operation to
securely transform amounts of data larger than a block.

This package simplifies the usage of AES-256-CBC.

Port of util/cbcutil/cbc.go
"""
import hashlib
import hmac
import os
from typing import IO, Optional, Protocol, Tuple, BinaryIO

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class File(Protocol):
    """Protocol for file-like objects that can be read, written at specific positions, and truncated."""

    def read(self, size: int = -1) -> bytes:
        """Read up to size bytes from the file."""
        ...

    def write_at(self, b: bytes, offset: int) -> int:
        """Write bytes at the specified offset."""
        ...

    def truncate(self, size: int) -> int:
        """Truncate the file to the specified size."""
        ...

    def stat(self) -> os.stat_result:
        """Return the stat information for the file."""
        ...


def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt a given cipher text with a provided key and initialization vector(iv).

    Args:
        key: The encryption key
        iv: The initialization vector
        ciphertext: The encrypted data

    Returns:
        The decrypted data

    Raises:
        ValueError: If the ciphertext is shorter than the block size
    """
    if len(ciphertext) < AES.block_size:
        raise ValueError(f"ciphertext is shorter than block size: {len(ciphertext)} / {AES.block_size}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted, AES.block_size)


def decrypt_file(key: bytes, iv: bytes, file: File) -> None:
    """
    Decrypt a file in place.

    Args:
        key: The encryption key
        iv: The initialization vector
        file: The file to decrypt

    Raises:
        ValueError: If the file size is not a multiple of the block size
        IOError: If there's an error reading from or writing to the file
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)

    stat_result = file.stat()
    file_size = stat_result.st_size

    if file_size % AES.block_size != 0:
        raise ValueError(f"file size is not a multiple of the block size: {file_size} / {AES.block_size}")

    buf_size = min(32 * 1024, file_size)
    buf = bytearray(buf_size)
    write_ptr = 0
    last_byte = 0

    while write_ptr < file_size:
        if write_ptr + buf_size > file_size:
            buf = buf[:file_size - write_ptr]

        data = file.read(len(buf))
        if len(data) != len(buf):
            raise IOError(f"failed to read full buffer: {len(data)} / {len(buf)}")

        buf[:] = cipher.decrypt(data)

        bytes_written = file.write_at(buf, write_ptr)
        if bytes_written != len(buf):
            raise IOError(f"failed to write full buffer: {bytes_written} / {len(buf)}")

        write_ptr += len(buf)
        last_byte = buf[-1]

    if last_byte > file_size:
        raise ValueError(f"padding is greater than the length: {last_byte} / {file_size}")

    file.truncate(file_size - last_byte)


def encrypt(key: bytes, iv: Optional[bytes], plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with a given key and an optional initialization vector(iv).

    Args:
        key: The encryption key
        iv: The initialization vector (if None, a random IV will be generated)
        plaintext: The data to encrypt

    Returns:
        The encrypted data (if iv was None, the first block_size bytes will be the IV)
    """
    # Calculate padding
    padded_data = pad(plaintext, AES.block_size)

    if iv is None:
        # Generate a random IV and prepend it to the ciphertext
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        return iv + ciphertext
    else:
        # Use the provided IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded_data)


def encrypt_stream(
    key: bytes,
    iv: bytes,
    mac_key: bytes,
    plaintext: IO[bytes],
    ciphertext: IO[bytes]
) -> Tuple[bytes, bytes, int, int]:
    """
    Encrypt a stream with key, IV, and MAC key.

    Args:
        key: The encryption key
        iv: The initialization vector
        mac_key: The key for HMAC calculation
        plaintext: The input stream to encrypt
        ciphertext: The output stream for encrypted data

    Returns:
        A tuple containing:
        - SHA-256 hash of the plaintext
        - SHA-256 hash of the ciphertext (including MAC)
        - Size of the plaintext in bytes
        - Size of the ciphertext in bytes (including padding and MAC)
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plain_hasher = hashlib.sha256()
    cipher_hasher = hashlib.sha256()
    cipher_mac = hmac.new(mac_key, iv, hashlib.sha256)

    has_writer_at = hasattr(ciphertext, "write_at")

    buf_size = 32 * 1024
    size = 0
    extra_size = 0
    write_ptr = 0
    has_more = True

    while has_more:
        # Read data chunk
        chunk = plaintext.read(buf_size)
        if not chunk:
            break

        plain_hasher.update(chunk)
        size += len(chunk)

        # Check if this is the last chunk and pad accordingly
        if len(chunk) < buf_size:
            # This is the last chunk, apply padding
            padding_size = AES.block_size - (size % AES.block_size)
            chunk = pad(chunk, AES.block_size)
            extra_size = padding_size
            has_more = False

        # Encrypt the data
        encrypted = cipher.encrypt(chunk)
        cipher_mac.update(encrypted)
        cipher_hasher.update(encrypted)

        if has_writer_at:
            ciphertext.write_at(encrypted, write_ptr)  # type: ignore[attr-defined]
            write_ptr += len(encrypted)
        else:
            ciphertext.write(encrypted)

    # Write MAC
    mac = cipher_mac.digest()[:10]
    extra_size += 10
    cipher_hasher.update(mac)

    if has_writer_at:
        ciphertext.write_at(mac, write_ptr)  # type: ignore[attr-defined]
    else:
        ciphertext.write(mac)

    return (
        plain_hasher.digest(),
        cipher_hasher.digest(),
        size,
        size + extra_size
    )
