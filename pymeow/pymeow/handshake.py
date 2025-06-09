"""
WhatsApp Web connection handshake implementation.

Port of whatsmeow/handshake.go
"""
import asyncio
import logging
from typing import Optional, TYPE_CHECKING

from .generated.waWa6 import WAWebProtobufsWa6_pb2
from .generated.waCert import WACert_pb2
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
WA_CERT_PUB_KEY = bytes([
    0x14, 0x23, 0x75, 0x57, 0x4d, 0xa, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e,
    0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c,
    0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b
])

logger = logging.getLogger(__name__)

async def do_handshake(client: 'Client', fs: FrameSocket, ephemeral_kp: KeyPair) -> Optional[Exception]:
    """
    Port of Go method doHandshake from handshake.go.

    Implements the Noise_XX_25519_AESGCM_SHA256 handshake for the WhatsApp web API.

    Args:
        client: The WhatsApp client instance
        fs: The frame socket for communication
        ephemeral_kp: The ephemeral key pair for handshake

    Returns:
        None if successful, Exception if failed
    """
    # TODO: Review NoiseHandshake implementation
    # TODO: Review FrameSocket implementation
    # TODO: Review KeyPair implementation

    try:
        nh = NoiseHandshake()
        nh.start(nh.NOISE_START_PATTERN, fs.header)
        nh.authenticate(ephemeral_kp.pub)

        # Create and marshal client hello
        try:
            data = WAWebProtobufsWa6_pb2.HandshakeMessage(
                clientHello=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientHello(
                    ephemeral=ephemeral_kp.pub
                )
            ).SerializeToString()
        except Exception as e:
            return Exception(f"failed to marshal handshake message: {e}")

        # Send handshake message
        try:
            await fs.send_frame(data)
        except Exception as e:
            return Exception(f"failed to send handshake message: {e}")

        # Wait for response with timeout
        try:
            resp = await asyncio.wait_for(
                fs.frames.get(),
                timeout=NOISE_HANDSHAKE_RESPONSE_TIMEOUT
            )
        except asyncio.TimeoutError as e:
            return e

        # Unmarshal handshake response
        try:
            handshake_response = WAWebProtobufsWa6_pb2.HandshakeMessage()
            handshake_response.ParseFromString(resp)
        except Exception as e:
            return e

        server_ephemeral = handshake_response.serverHello.ephemeral
        server_static_ciphertext = handshake_response.serverHello.static
        certificate_ciphertext = handshake_response.serverHello.payload

        if (len(server_ephemeral) != 32 or
            not server_static_ciphertext or
            not certificate_ciphertext):
            return Exception("missing parts of handshake response")

        # Process server ephemeral key
        nh.authenticate(server_ephemeral)
        try:
            nh.mix_shared_secret_into_key(ephemeral_kp.priv, server_ephemeral)
        except Exception as e:
            return e

        # Decrypt server static key
        try:
            static_decrypted = nh.decrypt(server_static_ciphertext)
        except Exception as e:
            return e

        if len(static_decrypted) != 32:
            return Exception(f"Unexpected length of server static plaintext {len(static_decrypted)} (expected 32)")

        # Mix server static key into handshake
        try:
            nh.mix_shared_secret_into_key(ephemeral_kp.priv, static_decrypted)
        except Exception as e:
            return e

        # Decrypt and verify certificate
        try:
            cert_decrypted = nh.decrypt(certificate_ciphertext)
        except Exception as e:
            return e

        if err := verify_server_cert(cert_decrypted, static_decrypted):
            return Exception(err)

        # Send client finish message
        encrypted_pubkey = nh.encrypt(client.store.noise_key.pub)
        try:
            nh.mix_shared_secret_into_key(client.store.noise_key.priv, server_ephemeral)
        except Exception as e:
            return e

        client_payload = get_client_payload(client.store)
        # Get client payload
        if clientpayload.get_client_payload is not None:  # todo: check what this does, it seems this always evaluates to true
            client_payload = clientpayload.get_client_payload(client.store)
        else:
            client_payload = client.store.get_client_payload()

        # Marshal client payload
        try:
            client_finish_payload_bytes = client_payload.SerializeToString()
        except Exception as e:
            return e
        encrypted_client_finish_payload = nh.encrypt(client_finish_payload_bytes)

        # Create and send client finish message
        try:
            data = WAWebProtobufsWa6_pb2.HandshakeMessage(
                clientFinish=WAWebProtobufsWa6_pb2.HandshakeMessage.ClientFinish(
                    static=encrypted_pubkey,
                    payload=encrypted_client_finish_payload
                )
            ).SerializeToString()
        except Exception as e:
            return e

        try:
            await fs.send_frame(data)
        except Exception as e:
            return e

        # Finish handshake and create noise socket
        try:
            ns = await nh.finish(fs, client.handle_frame, client.on_disconnect)
        except Exception as e:
            return e

        client.socket = ns

    except Exception as e:
        return e


def verify_server_cert(cert_decrypted: bytes, static_decrypted: bytes) -> Optional[Exception]:
    """
    Port of Go method verifyServerCert from handshake.go.

    Verify the server certificate chain.

    Args:
        cert_decrypted: The decrypted certificate data
        static_decrypted: The decrypted static key

    Returns:
        None if verification succeeds, Exception if it fails
    """
    # TODO: Review signal_protocol ecc module implementation

    try:
        # Parse certificate chain
        cert_chain = WACert_pb2.CertChain()
        cert_chain.ParseFromString(cert_decrypted)
    except Exception as e:
        return e

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
        return Exception("Missing parts of noise certificate")

    if len(intermediate_cert_signature) != 64:
        return Exception(f"Unexpected length of intermediate cert signature {len(intermediate_cert_signature)} (expected 64)")

    if len(leaf_cert_signature) != 64:
        return Exception(f"Unexpected length of leaf cert signature {len(leaf_cert_signature)} (expected 64)")

    # Verify intermediate certificate signature
    from signal_protocol import ecc
    if not ecc.verify_signature(ecc.new_djb_ec_public_key(WA_CERT_PUB_KEY), intermediate_cert_details_raw, intermediate_cert_signature):
        return Exception("failed to verify intermediate cert signature")

    # Parse intermediate cert details
    try:
        intermediate_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        intermediate_cert_details.ParseFromString(intermediate_cert_details_raw)
    except Exception as e:
        return e

    # Verify issuer serial - use issuerSerial (camelCase) not issuer_serial (snake_case)
    if intermediate_cert_details.issuerSerial != WA_CERT_ISSUER_SERIAL:
        return Exception(f"Unexpected intermediate issuer serial {intermediate_cert_details.issuerSerial} (expected {WA_CERT_ISSUER_SERIAL})")

    # Verify intermediate key length
    if len(intermediate_cert_details.key) != 32:
        return Exception(f"Unexpected length of intermediate cert key {len(intermediate_cert_details.key)} (expected 32)")

    # Verify leaf certificate signature
    if not ecc.verify_signature(ecc.new_djb_ec_public_key(intermediate_cert_details.key), leaf_cert_details_raw, leaf_cert_signature):
        return Exception("Failed to verify leaf cert signature")

    # Parse leaf certificate details
    try:
        leaf_cert_details = WACert_pb2.CertChain.NoiseCertificate.Details()
        leaf_cert_details.ParseFromString(leaf_cert_details_raw)
    except Exception as e:
        return e

    # Verify leaf issuer serial - use issuerSerial (camelCase) not issuer_serial (snake_case)
    if leaf_cert_details.issuerSerial != intermediate_cert_details.serial:
        return Exception(f"Unexpected leaf issuer serial {leaf_cert_details.issuerSerial} (expected {intermediate_cert_details.serial})")

    # Verify leaf key matches static key
    if leaf_cert_details.key != static_decrypted:
        return Exception("Cert key doesn't match decrypted static")

    return None
