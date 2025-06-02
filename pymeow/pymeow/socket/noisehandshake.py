"""
Noise protocol handshake implementation for WhatsApp Web.

Port of whatsmeow/socket/noisehandshake.go
"""
import hashlib
import struct
import threading
from typing import Optional, Tuple, Callable, Awaitable, Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..util.gcmutil import prepare

from .framesocket import FrameSocket
from .noisesocket import NoiseSocket, new_noise_socket


class NoiseHandshake:
    """
    Implements the Noise Protocol handshake for WhatsApp Web.

    This class handles the cryptographic handshake process that establishes
    a secure connection with the WhatsApp server.
    """

    # Noise protocol handshake pattern with null bytes padding
    # This matches the Go implementation's NoiseStartPattern constant
    NOISE_START_PATTERN = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"

    def __init__(self):
        """Initialize a new NoiseHandshake instance."""
        self.hash: bytes = b''
        self.salt: bytes = b''
        self.key: Optional[AESGCM] = None
        self.counter: int = 0
        self._counter_lock = threading.Lock()

    @staticmethod
    def _sha256_slice(data: bytes) -> bytes:
        """
        Compute the SHA-256 hash of data.

        Args:
            data: The data to hash

        Returns:
            The SHA-256 hash as bytes
        """
        return hashlib.sha256(data).digest()

    def start(self, pattern: str, header: bytes) -> None:
        """
        Start the handshake with the given pattern and header.

        Args:
            pattern: The noise pattern to use
            header: The header data to authenticate

        Raises:
            ValueError: If key preparation fails
        """
        # Convert pattern string to bytes if it's not already
        data = pattern.encode('utf-8') if isinstance(pattern, str) else pattern

        # If data is already 32 bytes, use it directly as the hash
        # Otherwise, compute the SHA-256 hash of the data
        if len(data) == 32:
            self.hash = data
        else:
            self.hash = self._sha256_slice(data)

        # Initialize salt with the hash
        self.salt = self.hash

        # Prepare the AES-GCM cipher with the hash as the key
        self.key = prepare(self.hash)

        # Authenticate the header
        self.authenticate(header)

    def authenticate(self, data: bytes) -> None:
        """
        Authenticate additional data into the handshake.

        Args:
            data: The data to authenticate
        """
        self.hash = self._sha256_slice(self.hash + data)

    def _post_increment_counter(self) -> int:
        """
        Atomically increment and return the previous counter value.

        Returns:
            The previous counter value
        """
        with self._counter_lock:
            count = self.counter
            self.counter += 1
            return count

    @staticmethod
    def _generate_iv(count: int) -> bytes:
        """
        Generate an initialization vector for AEAD encryption/decryption.

        Args:
            count: The message counter

        Returns:
            A 12-byte IV with the counter in the last 4 bytes
        """
        # Create a 12-byte IV with zeros
        iv = bytearray(12)
        # Pack the counter into the last 4 bytes in big-endian format
        # This matches the Go implementation in generateIV function
        struct.pack_into('>I', iv, 8, count)
        return bytes(iv)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext data.

        Args:
            plaintext: The data to encrypt

        Returns:
            The encrypted data

        Raises:
            ValueError: If encryption fails
        """
        if not self.key:
            raise ValueError("Encryption key not initialized")

        # Get the counter value and generate IV
        count = self._post_increment_counter()
        iv = self._generate_iv(count)

        # Encrypt the data using AESGCM with the hash as associated data
        # This matches the Go implementation which uses gcmutil.Encrypt
        try:
            ciphertext = self.key.encrypt(iv, plaintext, self.hash)
            # Authenticate the ciphertext
            self.authenticate(ciphertext)
            return ciphertext
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext data.

        Args:
            ciphertext: The data to decrypt

        Returns:
            The decrypted data

        Raises:
            ValueError: If decryption fails
        """
        if not self.key:
            raise ValueError("Decryption key not initialized")

        # Get the counter value and generate IV
        count = self._post_increment_counter()
        iv = self._generate_iv(count)

        try:
            # Decrypt the data using AESGCM with the hash as associated data
            # This matches the Go implementation which uses gcmutil.Decrypt
            plaintext = self.key.decrypt(iv, ciphertext, self.hash)
            # Authenticate the ciphertext after successful decryption
            self.authenticate(ciphertext)
            return plaintext
        except Exception as e:
            # Provide more detailed error message
            raise ValueError(f"Decryption failed: {e}")

    async def finish(self, fs: FrameSocket,
                    frame_handler: Callable[[bytes], Awaitable[None]],
                    disconnect_handler: Callable[["NoiseSocket", bool], Awaitable[None]]) -> NoiseSocket:
        """
        Finish the handshake and create a NoiseSocket.

        Args:
            fs: The underlying FrameSocket
            frame_handler: Callback for handling decrypted frames
            disconnect_handler: Callback for handling disconnections

        Returns:
            A new NoiseSocket instance

        Raises:
            ValueError: If key extraction or socket creation fails
        """
        try:
            write, read = self._extract_and_expand(self.salt, None)
            write_key = prepare(write)
            read_key = prepare(read)
            return await new_noise_socket(fs, write_key, read_key, frame_handler, disconnect_handler)
        except Exception as e:
            raise ValueError(f"Failed to finish handshake: {e}")

    def mix_shared_secret_into_key(self, priv: bytes, pub: bytes) -> None:
        """
        Mix a shared secret derived from private and public keys into the handshake.

        Args:
            priv: The private key (32 bytes)
            pub: The public key (32 bytes)

        Raises:
            ValueError: If key mixing fails
        """
        try:
            # Ensure keys are the correct length
            if len(priv) != 32 or len(pub) != 32:
                raise ValueError("Invalid key length")

            # Create X25519 key objects from the raw bytes
            private_key = X25519PrivateKey.from_private_bytes(priv)
            public_key = X25519PublicKey.from_public_bytes(pub)

            # Perform the X25519 scalar multiplication
            # This matches the Go implementation which uses curve25519.X25519
            secret = private_key.exchange(public_key)

            # Mix the shared secret into the key
            self.mix_into_key(secret)
        except Exception as e:
            raise ValueError(f"Failed to mix shared secret: {e}")

    def mix_into_key(self, data: bytes) -> None:
        """
        Mix additional data into the handshake key.

        Args:
            data: The data to mix

        Raises:
            ValueError: If key mixing fails
        """
        self.counter = 0
        try:
            write, read = self._extract_and_expand(self.salt, data)
            self.salt = write
            self.key = prepare(read)
        except Exception as e:
            raise ValueError(f"Failed to mix into key: {e}")

    def _extract_and_expand(self, salt: bytes, data: Optional[bytes]) -> Tuple[bytes, bytes]:
        """
        Extract and expand keys using HKDF.

        Args:
            salt: The salt value
            data: The input keying material (can be None)

        Returns:
            A tuple of (write_key, read_key)

        Raises:
            ValueError: If key extraction fails
        """
        try:
            if data is None:
                data = b''

            # Use a more direct approach to match the Go implementation
            # In Go: h := hkdf.New(sha256.New, data, salt, nil)
            # Then it reads 32 bytes twice from the same HKDF reader

            # Create a raw HKDF implementation
            import io
            import hmac

            # Step 1: Extract
            if not salt:
                salt = bytes([0] * 32)  # Use zero key if salt is empty
            prk = hmac.new(salt, data, hashlib.sha256).digest()

            # Step 2: Expand
            # Create an expandable output function
            info = b''
            t = b''
            okm = b''
            for i in range(1, 3):  # We need 2 blocks (64 bytes total)
                t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
                okm += t

            # Split the output into write and read keys
            write = okm[:32]
            read = okm[32:64]

            return write, read
        except Exception as e:
            raise ValueError(f"Failed to extract and expand keys: {e}")
