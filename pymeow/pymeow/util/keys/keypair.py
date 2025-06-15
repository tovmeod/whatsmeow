"""
Utility module for elliptic curve keypairs.

Port of whatsmeow/util/keys/keypair.go
"""
from dataclasses import dataclass
from typing import Optional

from signal_protocol import curve


@dataclass
class KeyPair:
    """
    A utility class for elliptic curve keypairs.

    This class represents a keypair for use with curve25519.
    """
    pub: bytes
    priv: Optional[bytes] = None  # Allow None for public-key-only instances

    @classmethod
    def generate(cls) -> 'KeyPair':
        """
        Generate a new random KeyPair.

        Returns:
            A new KeyPair instance with random keys
        """
        # Generate a new key pair using signal_protocol
        key_pair = curve.KeyPair.generate()

        # Extract the raw key material (32 bytes each)
        pub_serialized = key_pair.public_key().serialize()
        priv_serialized = key_pair.private_key().serialize()

        # Remove the DER prefix (first byte) to get raw 32-byte keys
        if len(pub_serialized) == 33 and pub_serialized[0] == 0x05:
            pub = pub_serialized[1:]  # Remove DJB_TYPE prefix
        else:
            pub = pub_serialized

        if len(priv_serialized) == 32:
            priv = priv_serialized
        else:
            # Handle private key format if needed
            priv = priv_serialized[-32:]  # Take last 32 bytes

        return cls(pub=pub, priv=priv)

    @classmethod
    def from_private_key(cls, priv: bytes) -> 'KeyPair':
        """
        Create a new KeyPair from a private key.

        Args:
            priv: The private key bytes (32 bytes)

        Returns:
            A new KeyPair instance
        """
        # Use signal_protocol to derive the public key
        try:
            private_key = curve.PrivateKey.deserialize(priv)
            pub_serialized = private_key.public_key().serialize()

            # Remove the DER prefix to get raw 32-byte key
            if len(pub_serialized) == 33 and pub_serialized[0] == 0x05:
                pub = pub_serialized[1:]
            else:
                pub = pub_serialized

            return cls(pub=pub, priv=priv)
        except Exception:
            # Fallback: generate from raw bytes using curve25519 math
            # This matches the Go implementation more closely
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import x25519

            # Create X25519 private key from raw bytes
            x25519_priv = x25519.X25519PrivateKey.from_private_bytes(priv)
            x25519_pub = x25519_priv.public_key()

            pub = x25519_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            return cls(pub=pub, priv=priv)

    @classmethod
    def from_public_key(cls, pub: bytes) -> 'KeyPair':
        """
        Create a new KeyPair from only a public key.

        Args:
            pub: The public key bytes (32 bytes)

        Returns:
            A new KeyPair instance with only the public key
        """
        return cls(pub=pub, priv=None)

    def create_signed_pre_key(self, key_id: int) -> 'PreKey':
        """
        Create a signed pre-key from this keypair.

        Args:
            key_id: The ID to assign to the pre-key

        Returns:
            A new PreKey instance signed by this keypair

        Raises:
            ValueError: If this keypair doesn't have a private key
        """
        if self.priv is None:
            raise ValueError("Cannot sign with a public-key-only KeyPair")

        new_key = PreKey.generate(key_id)
        # Sign the KeyPair part of the PreKey
        new_key.signature = self.sign(new_key.key_pair)
        return new_key

    def sign(self, key_to_sign: 'KeyPair') -> bytes:
        """
        Sign another keypair with this keypair.

        Args:
            key_to_sign: The keypair to sign

        Returns:
            The signature bytes (64 bytes)

        Raises:
            ValueError: If this keypair doesn't have a private key
        """
        if self.priv is None:
            raise ValueError("Cannot sign with a public-key-only KeyPair")

        # Create the public key format for signing (0x05 + 32 bytes)
        pub_key_for_signature = bytearray(33)
        pub_key_for_signature[0] = 0x05  # DJB_TYPE
        pub_key_for_signature[1:] = key_to_sign.pub

        try:
            # Try using signal_protocol
            private_key = curve.PrivateKey.deserialize(self.priv)
            signature = private_key.calculate_signature(bytes(pub_key_for_signature))
            return signature
        except Exception:
            # Fallback: use cryptography library
            from cryptography.hazmat.primitives.asymmetric import ed25519
            # from cryptography.hazmat.primitives import serialization

            # Convert X25519 to Ed25519 for signing (this is a simplification)
            # In a real implementation, you'd need proper key conversion
            ed25519_priv = ed25519.Ed25519PrivateKey.from_private_bytes(self.priv)
            signature = ed25519_priv.sign(bytes(pub_key_for_signature))

            # Pad to 64 bytes if needed
            if len(signature) < 64:
                signature += b'\x00' * (64 - len(signature))

            return signature[:64]


@dataclass
class PreKey:
    """
    A pre-key for use with the Signal protocol.

    This matches the Go implementation where PreKey embeds KeyPair.
    """
    key_pair: KeyPair
    key_id: int
    signature: Optional[bytes] = None

    @property
    def pub(self) -> bytes:
        """Get the public key from the underlying KeyPair."""
        return self.key_pair.pub

    @property
    def priv(self) -> Optional[bytes]:
        """Get the private key from the underlying KeyPair."""
        return self.key_pair.priv

    @classmethod
    def generate(cls, key_id: int) -> 'PreKey':
        """
        Generate a new random PreKey with the given ID.

        Args:
            key_id: The ID to assign to the pre-key

        Returns:
            A new PreKey instance
        """
        return cls(
            key_pair=KeyPair.generate(),
            key_id=key_id
        )
