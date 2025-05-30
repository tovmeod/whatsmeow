"""
Utility module for elliptic curve keypairs.

Port of whatsmeow/util/keys/keypair.go
"""
from dataclasses import dataclass, field
from typing import Optional, Tuple
import os

from libsignal.ecc.curve import Curve
from libsignal.ecc.djbec import DjbECPublicKey, DjbECPrivateKey


@dataclass
class KeyPair:
    """
    A utility class for elliptic curve keypairs.

    This class represents a keypair for use with curve25519.
    """
    pub: bytes
    priv: bytes

    @classmethod
    def from_private_key(cls, priv: bytes) -> 'KeyPair':
        """
        Create a new KeyPair from a private key.

        Args:
            priv: The private key bytes (32 bytes)

        Returns:
            A new KeyPair instance
        """
        pub = Curve.generatePublicKey(priv)
        return cls(pub=pub, priv=priv)

    @classmethod
    def generate(cls) -> 'KeyPair':
        """
        Generate a new random KeyPair.

        Returns:
            A new KeyPair instance with random keys
        """
        # Generate a random private key
        priv = Curve.generatePrivateKey()

        # In Go, these bit operations are performed:
        # priv[0] &= 248
        # priv[31] &= 127
        # priv[31] |= 64
        #
        # These operations ensure the private key is in the correct format for curve25519
        # The Python libsignal implementation already handles this internally

        return cls.from_private_key(priv)

    def create_signed_pre_key(self, key_id: int) -> 'PreKey':
        """
        Create a signed pre-key from this keypair.

        Args:
            key_id: The ID to assign to the pre-key

        Returns:
            A new PreKey instance signed by this keypair
        """
        new_key = PreKey.generate(key_id)
        new_key.signature = self.sign(new_key)
        return new_key

    def sign(self, key_to_sign: 'KeyPair') -> bytes:
        """
        Sign another keypair with this keypair.

        Args:
            key_to_sign: The keypair to sign

        Returns:
            The signature bytes (64 bytes)
        """
        # Create the public key format for signing (0x05 + 32 bytes)
        pub_key_for_signature = bytearray(33)
        pub_key_for_signature[0] = Curve.DJB_TYPE  # 0x05
        pub_key_for_signature[1:] = key_to_sign.pub

        # Create a DjbECPrivateKey from the raw private key
        private_key = DjbECPrivateKey(self.priv)

        # Calculate the signature
        signature = Curve.calculateSignature(private_key, bytes(pub_key_for_signature))
        return signature


@dataclass
class PreKey:
    """
    A pre-key for use with the Signal protocol.

    This class extends KeyPair with an ID and a signature.
    """
    key_pair: KeyPair
    key_id: int
    signature: Optional[bytes] = None

    @property
    def pub(self) -> bytes:
        """Get the public key from the underlying KeyPair."""
        return self.key_pair.pub

    @property
    def priv(self) -> bytes:
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
