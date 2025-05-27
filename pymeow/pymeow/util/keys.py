"""
Key handling utilities for WhatsApp.

Port of whatsmeow/util/keys/keys.go
"""
import os
from typing import Tuple

from .hkdfutil import expand_hmac

class KeyPair:
    """A public/private key pair."""
    def __init__(self, private: bytes, public: bytes):
        self.private = private
        self.public = public

def generate_signaling_key() -> bytes:
    """Generate a random 32-byte signaling key."""
    return os.urandom(32)

def derive_secrets(shared_key: bytes) -> Tuple[bytes, bytes]:
    """Derive encryption and MAC keys from a shared key."""
    enc_key = expand_hmac(shared_key, b"Encryption", 32)
    mac_key = expand_hmac(shared_key, b"Authentication", 32)
    return enc_key, mac_key
