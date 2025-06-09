"""
HKDF utility module.

Port of whatsmeow/util/hkdfutil/hkdf.go
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sha256(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Derive a key using HKDF with SHA-256.

    Args:
        key: The input key material
        salt: Salt value (a non-secret random value)
        info: Context and application specific information
        length: Length of the derived key in bytes

    Returns:
        The derived key of the specified length

    Raises:
        ValueError: If the key derivation fails
    """
    if length > 255:
        raise ValueError("Length is limited to 255 bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )

    derived_key = hkdf.derive(key)

    if len(derived_key) != length:
        raise ValueError(f"Didn't read enough bytes (got {len(derived_key)}, wanted {length})")

    return derived_key


def expand_hmac(key: bytes, info: bytes, length: int) -> bytes:
    """
    Derive a key using HKDF with SHA-256, without a salt.

    This is a convenience wrapper around sha256 that uses an empty salt.

    Args:
        key: The input key material
        info: Context and application specific information
        length: Length of the derived key in bytes

    Returns:
        The derived key of the specified length

    Raises:
        ValueError: If the key derivation fails
    """
    return sha256(key, b"", info, length)
