"""
WhatsApp Web connection handshake implementation.

Port of whatsmeow/handshake.go
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from .generated.waCert import WACert_pb2
from .generated.waWa6 import WAWebProtobufsWa6_pb2
from .socket.framesocket import FrameSocket
from .socket.noisehandshake import NoiseHandshake
from .store import clientpayload
from .store.clientpayload import get_client_payload
from .util.keys.keypair import KeyPair

if TYPE_CHECKING:
    from .client import Client

# Constants
NOISE_HANDSHAKE_RESPONSE_TIMEOUT = 20  # seconds
WA_CERT_ISSUER_SERIAL = 0
WA_CERT_PUB_KEY = bytes(
    [
        0x14,
        0x23,
        0x75,
        0x57,
        0x4D,
        0xA,
        0x58,
        0x71,
        0x66,
        0xAA,
        0xE7,
        0x1E,
        0xBE,
        0x51,
        0x64,
        0x37,
        0xC4,
        0xA2,
        0x8B,
        0x73,
        0xE3,
        0x69,
        0x5C,
        0x6C,
        0xE1,
        0xF7,
        0xF9,
        0x54,
        0x5D,
        0xA8,
        0xEE,
        0x6B,
    ]
)

logger = logging.getLogger(__name__)


async def do_handshake(client: "Client", fs: FrameSocket, ephemeral_kp: KeyPair) -> None:
    """
    Port of Go method doHandshake from handshake.go.

    Implements the Noise_XX_25519_AESGCM_SHA256 handshake for the WhatsApp web API.

    Args:
        client: The WhatsApp client instance
        fs: The frame socket for communication
        ephemeral_kp: The ephemeral key pair for handshake

    Raises:
        Exception
    """
    nh = NoiseHandshake()
    nh.start(nh.NOISE_START_PATTERN, fs.header)
    nh.authenticate(ephemeral_kp.pub)

    # Create and marshal client hello
    data = WAWebProtobufsWa6_pb2.HandshakeMessage(
        clientHello=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientHello(ephemeral=ephemeral_kp.pub)
    ).SerializeToString()
    # Send handshake message
    await fs.send_frame(data)
    # Wait for response with timeout
    resp = await asyncio.wait_for(fs.frames.get(), timeout=NOISE_HANDSHAKE_RESPONSE_TIMEOUT)
    # Unmarshal handshake response
    handshake_response = WAWebProtobufsWa6_pb2.HandshakeMessage()
    handshake_response.ParseFromString(bytes(resp))
    server_ephemeral = handshake_response.serverHello.ephemeral
    server_static_ciphertext = handshake_response.serverHello.static
    certificate_ciphertext = handshake_response.serverHello.payload

    if len(server_ephemeral) != 32 or not server_static_ciphertext or not certificate_ciphertext:
        raise Exception("missing parts of handshake response")

    # Process server ephemeral key
    nh.authenticate(server_ephemeral)
    assert ephemeral_kp.priv is not None
    nh.mix_shared_secret_into_key(ephemeral_kp.priv, server_ephemeral)
    # Decrypt server static key
    static_decrypted = nh.decrypt(server_static_ciphertext)
    if len(static_decrypted) != 32:
        raise Exception(f"Unexpected length of server static plaintext {len(static_decrypted)} (expected 32)")

    # Mix server static key into handshake
    nh.mix_shared_secret_into_key(ephemeral_kp.priv, static_decrypted)
    # Decrypt and verify certificate
    cert_decrypted = nh.decrypt(certificate_ciphertext)

    if err := verify_server_cert(cert_decrypted, static_decrypted):
        raise Exception(err)

    # Send client finish message
    encrypted_pubkey = nh.encrypt(client.store.noise_key.pub)
    assert client.store.noise_key.priv is not None
    nh.mix_shared_secret_into_key(client.store.noise_key.priv, server_ephemeral)

    client_payload = get_client_payload(client.store)
    # Get client payload
    if (
        clientpayload.get_client_payload is not None
    ):  # todo: check what this does, it seems this always evaluates to true
        client_payload = clientpayload.get_client_payload(client.store)
    else:
        client_payload = get_client_payload(client.store)

    # Marshal client payload
    client_finish_payload_bytes = client_payload.SerializeToString()
    encrypted_client_finish_payload = nh.encrypt(client_finish_payload_bytes)

    # Create and send client finish message
    data = WAWebProtobufsWa6_pb2.HandshakeMessage(
        clientFinish=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientFinish(
            static=encrypted_pubkey, payload=encrypted_client_finish_payload
        )
    ).SerializeToString()
    await fs.send_frame(data)
    # Finish handshake and create noise socket
    ns = await nh.finish(fs, client.handle_frame, client.on_disconnect)
    client.socket = ns


def verify_server_cert(cert_decrypted: bytes, static_decrypted: bytes) -> Optional[str]:
    """
    Port of Go method verifyServerCert from handshake.go.

    Verify the server certificate chain exactly as the Go implementation does.

    Args:
        cert_decrypted: The decrypted certificate data
        static_decrypted: The decrypted static key

    Returns:
        None if verification succeeds, error string if it fails
    """
    try:
        # Parse certificate chain
        cert_chain = WACert_pb2.CertChain()
        cert_chain.ParseFromString(cert_decrypted)

        # Extract certificate components (matching Go implementation)
        intermediate_cert_details_raw = cert_chain.intermediate.details
        intermediate_cert_signature = cert_chain.intermediate.signature
        leaf_cert_details_raw = cert_chain.leaf.details
        leaf_cert_signature = cert_chain.leaf.signature

        # Basic validation (matching Go implementation checks)
        if (
            intermediate_cert_details_raw is None
            or intermediate_cert_signature is None
            or leaf_cert_details_raw is None
            or leaf_cert_signature is None
        ):
            return "missing parts of noise certificate"

        if len(intermediate_cert_signature) != 64:
            return f"unexpected length of intermediate cert signature {len(intermediate_cert_signature)} (expected 64)"

        if len(leaf_cert_signature) != 64:
            return f"unexpected length of leaf cert signature {len(leaf_cert_signature)} (expected 64)"

        # Verify intermediate certificate signature with WhatsApp's root public key
        # This matches: ecc.VerifySignature(ecc.NewDjbECPublicKey(WACertPubKey), intermediateCertDetailsRaw, [64]byte(intermediateCertSignature))
        if not _verify_djb_signature(WA_CERT_PUB_KEY, intermediate_cert_details_raw, intermediate_cert_signature):
            return "failed to verify intermediate cert signature"

        # Parse intermediate certificate details
        intermediate_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        intermediate_cert_details.ParseFromString(intermediate_cert_details_raw)

        if intermediate_cert_details.issuerSerial != WA_CERT_ISSUER_SERIAL:
            return f"unexpected intermediate issuer serial {intermediate_cert_details.issuerSerial} (expected {WA_CERT_ISSUER_SERIAL})"

        if len(intermediate_cert_details.key) != 32:
            return f"unexpected length of intermediate cert key {len(intermediate_cert_details.key)} (expected 32)"

        # Verify leaf certificate signature with intermediate's public key
        # This matches: ecc.VerifySignature(ecc.NewDjbECPublicKey([32]byte(intermediateCertDetails.GetKey())), leafCertDetailsRaw, [64]byte(leafCertSignature))
        if not _verify_djb_signature(intermediate_cert_details.key, leaf_cert_details_raw, leaf_cert_signature):
            return "failed to verify leaf cert signature"

        # Parse leaf certificate details
        leaf_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        leaf_cert_details.ParseFromString(leaf_cert_details_raw)

        if leaf_cert_details.issuerSerial != intermediate_cert_details.serial:
            return f"unexpected leaf issuer serial {leaf_cert_details.issuerSerial} (expected {intermediate_cert_details.serial})"

        if leaf_cert_details.key != static_decrypted:
            return "cert key doesn't match decrypted static"

        logger.debug("Certificate verification completed successfully")
        return None

    except Exception as e:
        return f"certificate verification failed: {e}"


def _verify_djb_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify DJB signature exactly as the Go implementation does.

    This matches the Go code: ecc.VerifySignature(ecc.NewDjbECPublicKey(key), message, signature)

    Args:
        public_key: 32-byte DJB public key
        message: Message that was signed
        signature: 64-byte signature

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        from signal_protocol import curve

        # The Go implementation uses ecc.NewDjbECPublicKey which expects a 32-byte key
        if len(public_key) != 32:
            logger.debug(f"Invalid public key length: {len(public_key)} (expected 32)")
            return False

        if len(signature) != 64:
            logger.debug(f"Invalid signature length: {len(signature)} (expected 64)")
            return False

        # Create DJB public key from the raw 32 bytes - this matches Go's ecc.NewDjbECPublicKey
        # The signal_protocol library expects a type byte (0x05) followed by the 32-byte key
        djb_key = bytes([0x05]) + public_key
        public_key_obj = curve.PublicKey.deserialize(djb_key)

        # Verify the signature
        return public_key_obj.verify_signature(message, signature)

    except Exception as e:
        logger.debug(f"DJB signature verification failed: {e}")
        return False
