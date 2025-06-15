"""
GCM (Galois/Counter Mode) encryption and decryption utilities.

Port of util/gcmutil/gcm.go
"""
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def prepare(secret_key: bytes) -> AESGCM:
    """
    Prepare an AES-GCM cipher with the given secret key.

    Args:
        secret_key: The secret key to use for encryption/decryption

    Returns:
        An AESGCM object that can be used for encryption/decryption

    Raises:
        ValueError: If the key is invalid
    """
    try:
        return AESGCM(secret_key)
    except Exception as e:
        raise ValueError(f"Failed to initialize AES-GCM cipher: {e}")


def decrypt(secret_key: bytes, iv: bytes, ciphertext: bytes, additional_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt ciphertext using AES-GCM.

    Args:
        secret_key: The secret key to use for decryption
        iv: The initialization vector
        ciphertext: The encrypted data
        additional_data: Additional authenticated data (optional)

    Returns:
        The decrypted plaintext

    Raises:
        ValueError: If decryption fails
    """
    try:
        gcm = prepare(secret_key)
        return gcm.decrypt(iv, ciphertext, additional_data)
    except Exception as e:
        raise ValueError(f"Failed to decrypt: {e}")


def encrypt(secret_key: bytes, iv: bytes, plaintext: bytes, additional_data: Optional[bytes] = None) -> bytes:
    """
    Encrypt plaintext using AES-GCM.

    Args:
        secret_key: The secret key to use for encryption
        iv: The initialization vector
        plaintext: The data to encrypt
        additional_data: Additional authenticated data (optional)

    Returns:
        The encrypted ciphertext

    Raises:
        ValueError: If encryption fails
    """
    try:
        gcm = prepare(secret_key)
        return gcm.encrypt(iv, plaintext, additional_data)
    except Exception as e:
        raise ValueError(f"Failed to encrypt: {e}")
