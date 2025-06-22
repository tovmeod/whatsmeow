"""
HKDF utility module.

Port of whatsmeow/util/hkdfutil/hkdf.go
"""

from .hkdf import expand_hmac, sha256

__all__ = ["expand_hmac", "sha256"]
