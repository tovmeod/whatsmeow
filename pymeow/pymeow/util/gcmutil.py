"""
GCM utilities for WhatsApp.

Port of whatsmeow/util/gcmutil/gcmutil.go
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_gcm(key: bytes, nonce: bytes, data: bytes, associated_data: bytes = None) -> bytes:
    """Decrypt data using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, associated_data)

def encrypt_gcm(key: bytes, nonce: bytes, data: bytes, associated_data: bytes = None) -> bytes:
    """Encrypt data using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, associated_data)
