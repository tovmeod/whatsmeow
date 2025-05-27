"""
HKDF utilities for WhatsApp.

Port of whatsmeow/util/hkdfutil/hkdfutil.go
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def expand_hmac(key: bytes, info: bytes, length: int) -> bytes:
    """Expand a key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key)
