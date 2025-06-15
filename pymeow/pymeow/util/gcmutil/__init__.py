"""
GCM utility module initialization.

Port of util/gcmutil
"""

from .gcm import decrypt, encrypt, prepare

__all__ = ["decrypt", "encrypt", "prepare"]
