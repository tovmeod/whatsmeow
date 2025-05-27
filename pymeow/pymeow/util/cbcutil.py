"""
CBC utilities for WhatsApp.

Port of whatsmeow/util/cbcutil/cbcutil.go
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def decrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Decrypt data using AES-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt data using AES-CBC."""
    # Add PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()
