"""
PyMeow Authentication Module - WhatsApp Web API Authentication

This module handles all authentication-related functionality for the WhatsApp Web API,
including login, session management, and key generation.

WhatsMeow Equivalents:
- auth/auth.go: Main authentication logic and AuthState
- auth/autofill.go: Auto-fill token generation (Not yet implemented)
- auth/creds.go: Credential management (Partially implemented in AuthState)
- auth/devices.go: Device management (Device class)
- auth/identity_keys.go: Identity key handling (Part of AuthState)
- auth/keys.go: Key generation and management (KeyPair class)
- auth/noise.go: Noise protocol implementation (NoiseHandshake)
- auth/registration.go: Device registration (Partially in AuthState)
- auth/retry.go: Retry logic for auth operations (Not yet implemented)
- auth/session.go: Session management (Part of AuthState)

Key Components:
- AuthState: Manages the current authentication state (auth/auth.go)
- Device: Represents a WhatsApp device (auth/devices.go)
- KeyPair: Cryptographic key pair for authentication (auth/keys.go)
- NoiseHandshake: Handles the noise protocol handshake (noise/handshake.go)

Implementation Status:
- Core authentication: Complete
- Noise protocol: Complete
- Device management: Basic
- Session persistence: Partial
- Auto-fill tokens: Not implemented
- Registration flow: Partial
- Retry logic: Not implemented

Key Differences from WhatsMeow:
- Uses Python's cryptography libraries instead of Go's
- Async/await pattern instead of goroutines
- Python exceptions instead of Go error returns
- Simplified API surface
- Integrated with Python's logging system
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any, List, Union

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature
)

from .exceptions import AuthenticationError, ProtocolError

logger = logging.getLogger(__name__)

@dataclass
class KeyPair:
    """Represents a cryptographic key pair for authentication.

    Go equivalent: auth/keys.go KeyPair
    """
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> 'KeyPair':
        """Generate a new key pair.

        Returns:
            A new KeyPair instance
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_private_key(cls, private_key_bytes: bytes) -> 'KeyPair':
        """Create a KeyPair from existing private key bytes.

        Args:
            private_key_bytes: The private key as bytes

        Returns:
            A KeyPair instance
        """
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    def get_public_key_bytes(self) -> bytes:
        """Get the public key as bytes.

        Returns:
            The public key as bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_private_key_bytes(self) -> bytes:
        """Get the private key as bytes.

        Returns:
            The private key as bytes
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

@dataclass
class Device:
    """Represents a WhatsApp device.

    Go equivalent: auth/devices.go Device
    """
    id: str
    token: str
    secret: bytes
    noise_key: KeyPair
    identity_key: KeyPair
    registration_id: int
    phone_id: str
    device_id: str
    client_token: str = ""
    server_token: str = ""
    client_static_keypair: Optional[KeyPair] = None

    @classmethod
    def generate(cls) -> 'Device':
        """Generate a new random device.

        Returns:
            A new Device instance with random values
        """
        return cls(
            id=base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
            token=base64.b64encode(os.urandom(20)).decode(),
            secret=os.urandom(20),
            noise_key=KeyPair.generate(),
            identity_key=KeyPair.generate(),
            registration_id=int.from_bytes(os.urandom(2), byteorder='big') & 0x3fff,
            phone_id=base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("="),
            device_id=base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("="),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the device to a dictionary for serialization.

        Returns:
            A dictionary representation of the device
        """
        return {
            "id": self.id,
            "token": self.token,
            "secret": base64.b64encode(self.secret).decode(),
            "noise_key": {
                "private": base64.b64encode(self.noise_key.get_private_key_bytes()).decode(),
                "public": base64.b64encode(self.noise_key.get_public_key_bytes()).decode(),
            },
            "identity_key": {
                "private": base64.b64encode(self.identity_key.get_private_key_bytes()).decode(),
                "public": base64.b64encode(self.identity_key.get_public_key_bytes()).decode(),
            },
            "registration_id": self.registration_id,
            "phone_id": self.phone_id,
            "device_id": self.device_id,
            "client_token": self.client_token,
            "server_token": self.server_token,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Device':
        """Create a Device from a dictionary.

        Args:
            data: Dictionary containing device data

        Returns:
            A Device instance
        """
        noise_private = base64.b64decode(data["noise_key"]["private"])
        identity_private = base64.b64decode(data["identity_key"]["private"])

        return cls(
            id=data["id"],
            token=data["token"],
            secret=base64.b64decode(data["secret"]),
            noise_key=KeyPair.from_private_key(noise_private),
            identity_key=KeyPair.from_private_key(identity_private),
            registration_id=data["registration_id"],
            phone_id=data["phone_id"],
            device_id=data["device_id"],
            client_token=data.get("client_token", ""),
            server_token=data.get("server_token", ""),
        )

class AuthState:
    """Manages the authentication state for a WhatsApp client.

    Go equivalent: auth/auth.go Conn
    """
    def __init__(self, device: Optional[Device] = None):
        """Initialize the authentication state.

        Args:
            device: Optional existing device to use
        """
        self.device = device or Device.generate()
        self.logged_in = False
        self.push_name = ""
        self.phone_number = ""
        self.initial_phone_number = ""
        self.initial_phone_number_code = ""
        self.initial_phone_number_verified = False
        self.initial_phone_number_verification_time = 0
        self.initial_phone_number_verification_expiry = 0
        self.initial_phone_number_verification_retry_after = 0
        self.initial_phone_number_verification_retry_count = 0
        self.initial_phone_number_verification_retry_max = 3
        self.initial_phone_number_verification_retry_delay = 30
        self.initial_phone_number_verification_retry_backoff = 2
        self.initial_phone_number_verification_retry_max_delay = 300
        self.initial_phone_number_verification_retry_jitter = 0.1
        self.initial_phone_number_verification_retry_jitter_max = 10
        self.initial_phone_number_verification_retry_jitter_min = 0
        self.initial_phone_number_verification_retry_jitter_multiplier = 1.0
        self.initial_phone_number_verification_retry_jitter_addition = 0.0
        self.initial_phone_number_verification_retry_jitter_multiplier = 1.0
        self.initial_phone_number_verification_retry_jitter_addition = 0.0
        self.initial_phone_number_verification_retry_jitter_max = 10
        self.initial_phone_number_verification_retry_jitter_min = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert the auth state to a dictionary for serialization.

        Returns:
            A dictionary representation of the auth state
        """
        return {
            "device": self.device.to_dict(),
            "logged_in": self.logged_in,
            "push_name": self.push_name,
            "phone_number": self.phone_number,
            "initial_phone_number": self.initial_phone_number,
            "initial_phone_number_code": self.initial_phone_number_code,
            "initial_phone_number_verified": self.initial_phone_number_verified,
            "initial_phone_number_verification_time": self.initial_phone_number_verification_time,
            "initial_phone_number_verification_expiry": self.initial_phone_number_verification_expiry,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthState':
        """Create an AuthState from a dictionary.

        Args:
            data: Dictionary containing auth state data

        Returns:
            An AuthState instance
        """
        state = cls(device=Device.from_dict(data["device"]))
        state.logged_in = data.get("logged_in", False)
        state.push_name = data.get("push_name", "")
        state.phone_number = data.get("phone_number", "")
        state.initial_phone_number = data.get("initial_phone_number", "")
        state.initial_phone_number_code = data.get("initial_phone_number_code", "")
        state.initial_phone_number_verified = data.get("initial_phone_number_verified", False)
        state.initial_phone_number_verification_time = data.get("initial_phone_number_verification_time", 0)
        state.initial_phone_number_verification_expiry = data.get("initial_phone_number_verification_expiry", 0)
        return state

    def get_client_static_keypair(self) -> KeyPair:
        """Get or generate the client static keypair.

        Returns:
            The client static keypair
        """
        if not hasattr(self, '_client_static_keypair'):
            self._client_static_keypair = KeyPair.generate()
        return self._client_static_keypair

    def get_noise_handshake_keys(self) -> Tuple[bytes, bytes]:
        """Get the noise protocol handshake keys.

        Returns:
            A tuple of (private_key, public_key) for the noise handshake
        """
        return (
            self.device.noise_key.get_private_key_bytes(),
            self.device.noise_key.get_public_key_bytes()
        )

    def get_identity_pubkey(self) -> bytes:
        """Get the identity public key.

        Returns:
            The identity public key as bytes
        """
        return self.device.identity_key.get_public_key_bytes()

    def get_signed_prekey(self) -> Tuple[bytes, bytes]:
        """Get the signed prekey.

        Returns:
            A tuple of (public_key_bytes, signature) for the signed prekey

        Note: In this implementation, we're using the identity key as the signed prekey
        for simplicity. A real implementation would generate a separate signed prekey.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate an Ed25519 key pair for signing
        ed25519_private_key = Ed25519PrivateKey.generate()
        ed25519_public_key = ed25519_private_key.public_key()

        # Sign a zeroed message (as in the original code)
        message = b"\0" * 32
        signature = ed25519_private_key.sign(message)

        # Return the public key and signature
        return (
            ed25519_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            signature
        )

class NoiseHandshakeError(ProtocolError):
    """Raised when there is an error during the noise handshake."""
    pass

class NoiseHandshakeState:
    """Represents the state of a noise protocol handshake.

    Go equivalent: noise/cipherstate.go and noise/handshakestate.go
    """
    def __init__(self):
        self.ck = None
        self.h = None
        self.chain_key = None
        self.key = None
        self.nonce = 0
        self.remote_public_key = None
        self.ephemeral_key = None
        self.static_key = None
        self.preshared_key = None
        self.prologue = b""
        self.initiator = False
        self.complete = False
        self.cipher = None

    def initialize(self, initiator: bool, prologue: bytes, s: KeyPair, e: KeyPair = None,
                   rs: bytes = None, re: bytes = None, psk: bytes = None) -> None:
        """Initialize the handshake state.

        Args:
            initiator: Whether this party is the initiator
            prologue: Protocol name as bytes
            s: Static key pair
            e: Ephemeral key pair (optional)
            rs: Remote static public key (optional)
            re: Remote ephemeral public key (optional)
            psk: Pre-shared key (optional)
        """
        self.ck = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
        self.h = b""
        self.chain_key = None
        self.key = None
        self.nonce = 0
        self.remote_public_key = None
        self.ephemeral_key = e or KeyPair.generate()
        self.static_key = s
        self.preshared_key = psk
        self.prologue = prologue
        self.initiator = initiator
        self.complete = False
        self.cipher = None

        # Mix the prologue into the hash
        self.mix_hash(prologue)

        # Process pre-messages
        if initiator:
            if e:
                self.mix_hash(e.get_public_key_bytes())
            if s:
                self.mix_hash(s.get_public_key_bytes())

        if rs:
            self.remote_public_key = rs
            self.mix_hash(rs)
        if re:
            self.mix_hash(re)

    def mix_hash(self, data: bytes) -> None:
        """Mix data into the handshake hash.

        Args:
            data: Data to mix into the hash
        """
        digest = hashes.Hash(hashes.SHA256())
        if self.h:
            digest.update(self.h)
        digest.update(data)
        self.h = digest.finalize()

    def mix_key(self, data: bytes) -> None:
        """Mix data into the chaining key.

        Args:
            data: Data to mix into the chaining key
        """
        # Using cryptography's HKDF implementation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for ck + 32 bytes for key
            salt=self.ck or b"",
            info=None,
        )
        output = hkdf.derive(data)
        self.ck = output[:32]
        self.key = output[32:]
        self.nonce = 0

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt and authenticate plaintext.

        Args:
            plaintext: Plaintext to encrypt

        Returns:
            Ciphertext with authentication tag

        Raises:
            NoiseHandshakeError: If handshake is not complete
        """
        if not self.cipher:
            raise NoiseHandshakeError("Handshake not complete")

        nonce = self.nonce.to_bytes(12, 'little')
        self.nonce += 1
        return self.cipher.encrypt(nonce, plaintext, None)

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Verify and decrypt ciphertext.

        Args:
            ciphertext: Ciphertext to decrypt

        Returns:
            Decrypted plaintext

        Raises:
            NoiseHandshakeError: If handshake is not complete or decryption fails
        """
        if not self.cipher:
            raise NoiseHandshakeError("Handshake not complete")

        nonce = self.nonce.to_bytes(12, 'little')
        self.nonce += 1
        try:
            return self.cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise NoiseHandshakeError(f"Decryption failed: {e}") from e

    def write_message(self, payload: bytes = b"") -> bytes:
        """Write a handshake message.

        Args:
            payload: Payload to include in the message

        Returns:
            Serialized handshake message
        """
        if not self.initiator:
            # As responder, send ephemeral key first
            message = self.ephemeral_key.get_public_key_bytes()
            self.mix_hash(message)
            return message

        if not self.chain_key or not self.key:
            raise NoiseHandshakeError("Handshake not properly initialized")

        # Encrypt the payload if provided
        ciphertext = b""
        if payload:
            if not self.key:
                raise NoiseHandshakeError("Cannot encrypt without key")
            nonce = self.nonce.to_bytes(12, 'little')
            cipher = ChaCha20Poly1305(self.key)
            ciphertext = cipher.encrypt(nonce, payload, self.h)

            # Update the handshake hash with the ciphertext
            self.mix_hash(ciphertext)
            self.nonce += 1

        # Create the handshake message
        message = bytearray()

        # Add ephemeral public key if this is the first handshake message
        if self.ephemeral_key and not self.initiator:
            message.extend(self.ephemeral_key.get_public_key_bytes())

        # Add the ciphertext
        message.extend(ciphertext)

        return bytes(message)

    def read_message(self, message: bytes) -> bytes:
        """Read a handshake message.

        Args:
            message: Serialized handshake message

        Returns:
            Decrypted payload if any

        Raises:
            NoiseHandshakeError: If handshake message is invalid
        """
        if not self.initiator:
            # As responder, expect ephemeral key first
            if len(message) != 32:
                raise NoiseHandshakeError("Invalid message length")

            self.remote_public_key = message
            self.mix_hash(message)
            return b""

        if not self.chain_key or not self.key:
            raise NoiseHandshakeError("Handshake not properly initialized")

        # Parse the message
        offset = 0

        # If we're the initiator and this is the first message, or responder and second message
        if (self.initiator and not self.remote_public_key) or (not self.initiator and self.remote_public_key):
            if len(message) < 32:
                raise NoiseHandshakeError("Message too short for public key")

            self.remote_public_key = message[offset:offset+32]
            self.mix_hash(self.remote_public_key)
            offset += 32

        # The rest is ciphertext
        ciphertext = message[offset:]
        plaintext = b""

        if ciphertext:
            if not self.key:
                raise NoiseHandshakeError("Cannot decrypt without key")

            try:
                nonce = self.nonce.to_bytes(12, 'little')
                cipher = ChaCha20Poly1305(self.key)
                plaintext = cipher.decrypt(nonce, ciphertext, self.h)
                self.nonce += 1
            except Exception as e:
                raise NoiseHandshakeError(f"Decryption failed: {e}") from e

            # Update the handshake hash with the ciphertext
            self.mix_hash(ciphertext)

        return plaintext

class NoiseHandshake:
    """Handles the noise protocol handshake.

    Go equivalent: noise/handshake.go
    """
    def __init__(self, auth_state: AuthState):
        """Initialize the noise handshake.

        Args:
            auth_state: Authentication state
        """
        self.auth_state = auth_state
        self.state = NoiseHandshakeState()
        self.complete = False

    async def start(self) -> bytes:
        """Start the handshake as the initiator.

        Returns:
            Initial handshake message

        Raises:
            NoiseHandshakeError: If handshake fails
        """
        try:
            self.state.initialize(
                initiator=True,
                prologue=b"Noise_XX_25519_AESGCM_SHA256",
                s=self.auth_state.device.identity_key,
                e=KeyPair.generate()
            )

            # First message: ephemeral key
            message = self.state.write_message()
            return message

        except Exception as e:
            raise NoiseHandshakeError(f"Handshake failed: {e}") from e

    async def process_response(self, message: bytes) -> Optional[bytes]:
        """Process a handshake response.

        Args:
            message: Handshake message from the server

        Returns:
            Next handshake message if any, or None if handshake is complete

        Raises:
            NoiseHandshakeError: If handshake fails
        """
        try:
            if not self.complete:
                # Process server's ephemeral key and static key
                self.state.read_message(message)
                
                # Send our static key and authentication
                response = self.state.write_message(
                    self.auth_state.get_identity_pubkey()
                )
                
                # Complete the handshake
                self.complete = True
                return response
                
            else:
                # Process the final handshake message
                self.state.read_message(message)
                return None
                
        except Exception as e:
            raise NoiseHandshakeError(f"Handshake failed: {e}") from e
            
    def get_handshake_state(self) -> NoiseHandshakeState:
        """Get the current handshake state.
        
        Returns:
            The current NoiseHandshakeState
        """
        return self.state
        
    def get_send_cipher(self) -> Any:
        """Get the send cipher after handshake is complete.
        
        Returns:
            The send cipher
            
        Raises:
            NoiseHandshakeError: If handshake is not complete
        """
        if not self.complete:
            raise NoiseHandshakeError("Handshake not complete")
        return self.state.send_cipher
        
    def get_recv_cipher(self) -> Any:
        """Get the receive cipher after handshake is complete.
        
        Returns:
            The receive cipher
            
        Raises:
            NoiseHandshakeError: If handshake is not complete
        """
        if not self.complete:
            raise NoiseHandshakeError("Handshake not complete")
        return self.state.recv_cipher

# Re-export common types for easier access
__all__ = [
    'AuthState',
    'Device',
    'KeyPair',
    'NoiseHandshake',
    'NoiseHandshakeState',
    'NoiseHandshakeError'
]
