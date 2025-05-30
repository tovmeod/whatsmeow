"""
HKDF utility module.

Port of whatsmeow/util/hkdfutil/hkdf.go
"""
from .hkdf import sha256, expand_hmac

__all__ = ["sha256", "expand_hmac"]
