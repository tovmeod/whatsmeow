"""
WhatsApp Web connection handshake implementation.

Port of whatsmeow/handshake.go
"""
import asyncio
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Callable, Any, List

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .generated.waWa6 import WAWebProtobufsWa6_pb2
from .generated.waCert import WACert_pb2
from .socket.framesocket import FrameSocket
from .socket.noisehandshake import NoiseHandshake
from .socket.noisesocket import NoiseSocket
from .util.keys.keypair import KeyPair
from .exceptions import PymeowError, ProtocolError, AuthenticationError

# Constants
NOISE_HANDSHAKE_RESPONSE_TIMEOUT = 20  # seconds
WA_CERT_ISSUER_SERIAL = 0
WA_CERT_PUB_KEY = bytes([
    0x14, 0x23, 0x75, 0x57, 0x4d, 0xa, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e,
    0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c,
    0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b
])

class HandshakeError(ProtocolError):
    """Raised when handshake fails."""
    pass

class CertificateVerificationError(AuthenticationError):
    """Raised when certificate verification fails."""
    pass

class Client:
    """Client for WhatsApp Web API.

    This is a partial implementation that only includes the handshake functionality.
    """

    def __init__(self):
        """Initialize the client."""
        self.socket: Optional[NoiseSocket] = None
        self.store = None
        self.get_client_payload: Optional[Callable] = None

    async def do_handshake(self, fs: FrameSocket, ephemeral_kp: KeyPair) -> None:
        """Implements the Noise_XX_25519_AESGCM_SHA256 handshake for the WhatsApp web API.

        Args:
            fs: The frame socket to use for communication
            ephemeral_kp: The ephemeral key pair to use for the handshake

        Raises:
            HandshakeError: If the handshake fails
            CertificateVerificationError: If certificate verification fails
            asyncio.TimeoutError: If handshake times out
        """
        try:
            nh = NoiseHandshake()
            nh.start(NoiseHandshake.NOISE_START_PATTERN, fs.header)
            nh.authenticate(ephemeral_kp.public)

            # Create and send client hello message
            data = WAWebProtobufsWa6_pb2.HandshakeMessage(
                client_hello=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientHello(
                    ephemeral=ephemeral_kp.public
                )
            ).SerializeToString()

            await fs.send_frame(data)

            # Wait for server response
            try:
                resp = await asyncio.wait_for(fs.frames.get(), NOISE_HANDSHAKE_RESPONSE_TIMEOUT)
            except asyncio.TimeoutError:
                raise HandshakeError("Timed out waiting for handshake response")

            # Parse server response
            try:
                handshake_response = WAWebProtobufsWa6_pb2.HandshakeMessage()
                handshake_response.ParseFromString(resp)
            except Exception as e:
                raise HandshakeError(f"Failed to unmarshal handshake response: {e}")

            server_ephemeral = handshake_response.server_hello.ephemeral
            server_static_ciphertext = handshake_response.server_hello.static
            certificate_ciphertext = handshake_response.server_hello.payload

            if (len(server_ephemeral) != 32 or
                not server_static_ciphertext or
                not certificate_ciphertext):
                raise HandshakeError("Missing parts of handshake response")

            # Process server ephemeral key
            nh.authenticate(server_ephemeral)
            try:
                nh.mix_shared_secret_into_key(ephemeral_kp.private, server_ephemeral)
            except Exception as e:
                raise HandshakeError(f"Failed to mix server ephemeral key in: {e}")

            # Decrypt server static key
            try:
                static_decrypted = nh.decrypt(server_static_ciphertext)
            except Exception as e:
                raise HandshakeError(f"Failed to decrypt server static ciphertext: {e}")

            if len(static_decrypted) != 32:
                raise HandshakeError(f"Unexpected length of server static plaintext {len(static_decrypted)} (expected 32)")

            # Mix server static key into handshake
            try:
                nh.mix_shared_secret_into_key(ephemeral_kp.private, static_decrypted)
            except Exception as e:
                raise HandshakeError(f"Failed to mix server static key in: {e}")

            # Decrypt and verify certificate
            try:
                cert_decrypted = nh.decrypt(certificate_ciphertext)
            except Exception as e:
                raise HandshakeError(f"Failed to decrypt noise certificate ciphertext: {e}")

            try:
                verify_server_cert(cert_decrypted, static_decrypted)
            except Exception as e:
                raise CertificateVerificationError(f"Failed to verify server cert: {e}")

            # Send client finish message
            encrypted_pubkey = nh.encrypt(self.store.noise_key.public)
            try:
                nh.mix_shared_secret_into_key(self.store.noise_key.private, server_ephemeral)
            except Exception as e:
                raise HandshakeError(f"Failed to mix noise private key in: {e}")

            # Get client payload
            client_payload = None
            if self.get_client_payload:
                client_payload = self.get_client_payload()
            else:
                client_payload = self.store.get_client_payload()

            # Serialize and encrypt client payload
            try:
                client_finish_payload_bytes = client_payload.SerializeToString()
            except Exception as e:
                raise HandshakeError(f"Failed to marshal client finish payload: {e}")

            encrypted_client_finish_payload = nh.encrypt(client_finish_payload_bytes)

            # Create and send client finish message
            try:
                data = WAWebProtobufsWa6_pb2.HandshakeMessage(
                    client_finish=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientFinish(
                        static=encrypted_pubkey,
                        payload=encrypted_client_finish_payload
                    )
                ).SerializeToString()
            except Exception as e:
                raise HandshakeError(f"Failed to marshal handshake finish message: {e}")

            await fs.send_frame(data)

            # Finish handshake and create noise socket
            try:
                ns = await nh.finish(fs, self.handle_frame, self.on_disconnect)
            except Exception as e:
                raise HandshakeError(f"Failed to create noise socket: {e}")

            self.socket = ns

        except (HandshakeError, CertificateVerificationError, asyncio.TimeoutError):
            raise
        except Exception as e:
            raise HandshakeError(f"Unexpected handshake error: {e}")

    def handle_frame(self, data: bytes) -> None:
        """Handle a frame received from the server.

        Args:
            data: The frame data
        """
        pass

    def on_disconnect(self, reason: str) -> None:
        """Handle a disconnection event.

        Args:
            reason: The reason for disconnection
        """
        pass

def verify_server_cert(cert_decrypted: bytes, static_decrypted: bytes) -> None:
    """Verify the server certificate.

    Args:
        cert_decrypted: The decrypted certificate
        static_decrypted: The decrypted static key

    Raises:
        CertificateVerificationError: If certificate verification fails
    """
    try:
        # Parse certificate chain
        cert_chain = WACert_pb2.CertChain()
        cert_chain.ParseFromString(cert_decrypted)
    except Exception as e:
        raise CertificateVerificationError(f"Failed to unmarshal noise certificate: {e}")

    # Extract certificate details
    intermediate_cert_details_raw = cert_chain.intermediate.details
    intermediate_cert_signature = cert_chain.intermediate.signature
    leaf_cert_details_raw = cert_chain.leaf.details
    leaf_cert_signature = cert_chain.leaf.signature

    # Validate certificate parts
    if (not intermediate_cert_details_raw or
        not intermediate_cert_signature or
        not leaf_cert_details_raw or
        not leaf_cert_signature):
        raise CertificateVerificationError("Missing parts of noise certificate")

    if len(intermediate_cert_signature) != 64:
        raise CertificateVerificationError(f"Unexpected length of intermediate cert signature {len(intermediate_cert_signature)} (expected 64)")

    if len(leaf_cert_signature) != 64:
        raise CertificateVerificationError(f"Unexpected length of leaf cert signature {len(leaf_cert_signature)} (expected 64)")

    # Verify intermediate certificate signature
    if not verify_signature(WA_CERT_PUB_KEY, intermediate_cert_details_raw, intermediate_cert_signature):
        raise CertificateVerificationError("Failed to verify intermediate cert signature")

    # Parse intermediate certificate details
    try:
        intermediate_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        intermediate_cert_details.ParseFromString(intermediate_cert_details_raw)
    except Exception as e:
        raise CertificateVerificationError(f"Failed to unmarshal intermediate certificate details: {e}")

    # Verify issuer serial
    if intermediate_cert_details.issuer_serial != WA_CERT_ISSUER_SERIAL:
        raise CertificateVerificationError(f"Unexpected intermediate issuer serial {intermediate_cert_details.issuer_serial} (expected {WA_CERT_ISSUER_SERIAL})")

    # Verify intermediate key length
    if len(intermediate_cert_details.key) != 32:
        raise CertificateVerificationError(f"Unexpected length of intermediate cert key {len(intermediate_cert_details.key)} (expected 32)")

    # Verify leaf certificate signature
    if not verify_signature(intermediate_cert_details.key, leaf_cert_details_raw, leaf_cert_signature):
        raise CertificateVerificationError("Failed to verify leaf cert signature")

    # Parse leaf certificate details
    try:
        leaf_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        leaf_cert_details.ParseFromString(leaf_cert_details_raw)
    except Exception as e:
        raise CertificateVerificationError(f"Failed to unmarshal leaf certificate details: {e}")

    # Verify leaf issuer serial
    if leaf_cert_details.issuer_serial != intermediate_cert_details.serial:
        raise CertificateVerificationError(f"Unexpected leaf issuer serial {leaf_cert_details.issuer_serial} (expected {intermediate_cert_details.serial})")

    # Verify leaf key matches static key
    if leaf_cert_details.key != static_decrypted:
        raise CertificateVerificationError("Cert key doesn't match decrypted static")

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature using Ed25519.

    Args:
        public_key: The public key to use for verification (32 bytes)
        message: The message that was signed
        signature: The signature to verify (64 bytes)

    Returns:
        True if the signature is valid, False otherwise
    """
    try:
        # Create Ed25519 public key from bytes
        ed25519_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)

        # Verify signature
        ed25519_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False
