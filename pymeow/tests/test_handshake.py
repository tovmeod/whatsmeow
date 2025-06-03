"""
Tests for the handshake functionality.

This tests the handshake process between the client and server.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

from ..pymeow.handshake import do_handshake, HandshakeError, CertificateVerificationError
from ..pymeow.socket.framesocket import FrameSocket
from ..pymeow.socket.noisehandshake import NoiseHandshake
from ..pymeow.socket.noisesocket import NoiseSocket
from ..pymeow.util.keys.keypair import KeyPair
from ..pymeow.generated.waWa6.WAWebProtobufsWa6_pb2 import HandshakeMessage

# Real test values captured from logs
SAMPLE_EPHEMERAL_KEYPAIR = {
    'pub': bytes.fromhex('e5a4bfbeb6df8f89938b2cf57850f0cde1fe7ab4026c2491588d1e907e99a338'),
    'priv': bytes.fromhex('08e1125a54b0869c914566f25f09bc551f069307d755da161a7d14d81b0e094d')
}

SAMPLE_SERVER_RESPONSE = {
    'server_ephemeral': bytes.fromhex('de6940113e823ab66e680923f127c6c9d384dffaffcb3e09a75fcd60f470f729'),
    'server_static_ciphertext': bytes.fromhex('81dcf0f762f4bb6512ab633f63e300c12ff0b6a6a6b7d69342d94591136dd9d3aeaff339b8b933a5ee23e2dc2b175e01'),
    'certificate_ciphertext': bytes.fromhex('39fd0a49c4976ac74e35471d1c92c0b463decd568f53f96c8b8eb12e1b9f56c50551544d89e444d4b798c9d5182bb365609a1368223a5dd95ad3097d45a3aa60ee3f8f284ad1f343dffaee5e980b2aeba8150e4608aab816d26e80b048bb0636f6aa8f28818b9bb8dce7b71edb10fb3aefcc8933e17090a9de9f2abf8f2d778971342dc450e6fed7a6f1dbdb1551313d3798612c5262a2c9088fd35af5f83b91cbe208c9f93b47051967d4e18b7226cdaee5f23872f09162e0617526c623260ebb73296d752f074245504d3300de1190719d7e0a918a9ead2a2bcb22d2f946ecb1b0831f5111dfc5e936f78dcb26ffea37232172162104b8481be6a8d4e7b95d37')
}

SAMPLE_STATIC_DECRYPTED = bytes.fromhex('6f53b211b38d5026094a378e5b5efd2c1d8ab1d28fac06c4f9fc97e44a6dfc68')
SAMPLE_CERT_DECRYPTED = bytes.fromhex('0a770a3308c70210031a206f53b211b38d5026094a378e5b5efd2c1d8ab1d28fac06c4f9fc97e44a6dfc6820d0bbf3bd0628d0f58bc30612408c3bfaec9868e6edd6d17d3470da33915c736695bd0e4ac0cfe63caf1a5d40214737256f6250087fe4195066ff0500356a5561960e0e9106b3ae751bb0e8d50512760a32080310001a201c51a9ac303994c6c8d0b92ea1878a533476599cc599fbea35997d9aa90cce62208091aebe0628ffdeb7dc061240270f294648539fed4870e25054dd4e95983aba29189c2ba6c8eeda7055555f753740f5ec192ab64c26c26d6ade6d20b9f774aee37120a6b20395f53c66058507')


def create_mock_client():
    """Create a mock client for testing."""
    mock_client = MagicMock()
    mock_client.store = MagicMock()
    mock_client.store.noise_key = MagicMock()
    mock_client.store.noise_key.pub = b'\x01' * 32
    mock_client.store.noise_key.priv = b'\x02' * 32
    mock_client.socket = None
    return mock_client


def create_mock_frame_socket():
    """Create a mock frame socket for testing."""
    mock_fs = MagicMock()
    mock_fs.header = b'test_header'
    mock_fs.send_frame = AsyncMock()
    mock_fs.frames = asyncio.Queue()
    return mock_fs


def create_mock_ephemeral_keypair():
    """Create a mock ephemeral key pair for testing."""
    mock_ephemeral_kp = MagicMock(spec=KeyPair)
    mock_ephemeral_kp.pub = SAMPLE_EPHEMERAL_KEYPAIR['pub']
    mock_ephemeral_kp.priv = SAMPLE_EPHEMERAL_KEYPAIR['priv']
    return mock_ephemeral_kp


@pytest.mark.asyncio
async def test_do_handshake_success():
    """Test successful handshake."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create mock server response
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = SAMPLE_SERVER_RESPONSE['server_ephemeral']
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake class and its methods
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()
        mock_nh.mix_shared_secret_into_key = MagicMock()
        mock_nh.decrypt = MagicMock(side_effect=[
            SAMPLE_STATIC_DECRYPTED,  # First call returns static_decrypted
            SAMPLE_CERT_DECRYPTED     # Second call returns cert_decrypted
        ])
        mock_nh.encrypt = MagicMock(side_effect=[
            b'encrypted_pubkey',      # First call for client public key
            b'encrypted_payload'      # Second call for client payload
        ])

        # Create a mock noise socket
        mock_noise_socket = MagicMock(spec=NoiseSocket)
        mock_nh.finish = AsyncMock(return_value=mock_noise_socket)

        # Mock verify_server_cert function
        with patch('pymeow.pymeow.handshake.verify_server_cert', MagicMock()) as mock_verify:
            # Mock get_client_payload function
            with patch('pymeow.pymeow.handshake.get_client_payload') as mock_get_payload:
                mock_payload = MagicMock()
                mock_payload.SerializeToString = MagicMock(return_value=b'client_payload')
                mock_get_payload.return_value = mock_payload

                # Call the function under test
                await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)

                # Verify NoiseHandshake was created
                mock_nh_class.assert_called_once()

                # Verify method calls
                mock_nh.start.assert_called_once_with(mock_nh.NOISE_START_PATTERN, mock_fs.header)

                # Verify authenticate calls (ephemeral and server ephemeral)
                expected_auth_calls = [
                    call(mock_ephemeral_kp.pub),
                    call(SAMPLE_SERVER_RESPONSE['server_ephemeral'])
                ]
                mock_nh.authenticate.assert_has_calls(expected_auth_calls)

                # Verify decrypt calls
                expected_decrypt_calls = [
                    call(SAMPLE_SERVER_RESPONSE['server_static_ciphertext']),
                    call(SAMPLE_SERVER_RESPONSE['certificate_ciphertext'])
                ]
                mock_nh.decrypt.assert_has_calls(expected_decrypt_calls)

                # Verify certificate verification
                mock_verify.assert_called_once_with(SAMPLE_CERT_DECRYPTED, SAMPLE_STATIC_DECRYPTED)

                # Verify encryption calls
                expected_encrypt_calls = [
                    call(mock_client.store.noise_key.pub),
                    call(b'client_payload')
                ]
                mock_nh.encrypt.assert_has_calls(expected_encrypt_calls)

                # Verify finish was called
                mock_nh.finish.assert_called_once()

                # Verify client socket was set
                assert mock_client.socket is mock_noise_socket


@pytest.mark.asyncio
async def test_do_handshake_timeout():
    """Test handshake timeout."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()

        # Mock asyncio.wait_for to raise TimeoutError
        with patch('asyncio.wait_for', AsyncMock(side_effect=asyncio.TimeoutError())):
            # Call the function under test and expect HandshakeError
            with pytest.raises(HandshakeError, match="Timed out waiting for handshake response"):
                await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)


@pytest.mark.asyncio
async def test_do_handshake_certificate_verification_error():
    """Test handshake with certificate verification error."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create mock server response
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = SAMPLE_SERVER_RESPONSE['server_ephemeral']
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()
        mock_nh.mix_shared_secret_into_key = MagicMock()
        mock_nh.decrypt = MagicMock(side_effect=[
            SAMPLE_STATIC_DECRYPTED,  # First call returns static_decrypted
            SAMPLE_CERT_DECRYPTED     # Second call returns cert_decrypted
        ])

        # Mock verify_server_cert to raise CertificateVerificationError
        with patch('pymeow.pymeow.handshake.verify_server_cert',
                   MagicMock(side_effect=CertificateVerificationError("Test error"))) as mock_verify:
            # Call the function under test and expect CertificateVerificationError
            with pytest.raises(CertificateVerificationError, match="Failed to verify server certificate"):
                await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)

            # Verify method calls
            mock_verify.assert_called_once_with(SAMPLE_CERT_DECRYPTED, SAMPLE_STATIC_DECRYPTED)


@pytest.mark.asyncio
async def test_do_handshake_missing_server_response_parts():
    """Test handshake with missing parts in server response."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create incomplete server response (missing ephemeral)
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = b''  # Missing ephemeral key
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()

        # Call the function under test and expect HandshakeError
        with pytest.raises(HandshakeError, match="Missing parts of handshake response"):
            await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)


@pytest.mark.asyncio
async def test_do_handshake_invalid_static_length():
    """Test handshake with invalid static key length."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create mock server response
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = SAMPLE_SERVER_RESPONSE['server_ephemeral']
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()
        mock_nh.mix_shared_secret_into_key = MagicMock()
        mock_nh.decrypt = MagicMock(side_effect=[
            b'invalid_length',  # Wrong length (should be 32 bytes)
            SAMPLE_CERT_DECRYPTED
        ])

        # Call the function under test and expect HandshakeError
        with pytest.raises(HandshakeError, match="Unexpected length of server static plaintext"):
            await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)


@pytest.mark.asyncio
async def test_do_handshake_invalid_handshake_response():
    """Test handshake with invalid handshake response format."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Add invalid response to frame socket queue
    await mock_fs.frames.put(b'invalid_protobuf_data')

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()

        # Call the function under test and expect HandshakeError
        with pytest.raises(HandshakeError, match="Failed to unmarshal handshake response"):
            await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)


@pytest.mark.asyncio
async def test_do_handshake_decrypt_failure():
    """Test handshake with decryption failure."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create mock server response
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = SAMPLE_SERVER_RESPONSE['server_ephemeral']
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()
        mock_nh.mix_shared_secret_into_key = MagicMock()
        # First decrypt call fails
        mock_nh.decrypt = MagicMock(side_effect=Exception("Decryption failed"))

        # Call the function under test and expect HandshakeError
        with pytest.raises(HandshakeError, match="Failed to decrypt server static ciphertext"):
            await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)


@pytest.mark.asyncio
async def test_do_handshake_finish_failure():
    """Test handshake with finish failure."""
    # Create test instances
    mock_client = create_mock_client()
    mock_fs = create_mock_frame_socket()
    mock_ephemeral_kp = create_mock_ephemeral_keypair()

    # Create mock server response
    server_response = HandshakeMessage()
    server_hello = HandshakeMessage.ServerHello()
    server_hello.ephemeral = SAMPLE_SERVER_RESPONSE['server_ephemeral']
    server_hello.static = SAMPLE_SERVER_RESPONSE['server_static_ciphertext']
    server_hello.payload = SAMPLE_SERVER_RESPONSE['certificate_ciphertext']
    server_response.serverHello.CopyFrom(server_hello)

    # Add server response to frame socket queue
    await mock_fs.frames.put(server_response.SerializeToString())

    # Mock NoiseHandshake
    with patch('pymeow.pymeow.handshake.NoiseHandshake') as mock_nh_class:
        mock_nh = mock_nh_class.return_value
        mock_nh.NOISE_START_PATTERN = b'Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00'
        mock_nh.start = MagicMock()
        mock_nh.authenticate = MagicMock()
        mock_nh.mix_shared_secret_into_key = MagicMock()
        mock_nh.decrypt = MagicMock(side_effect=[
            SAMPLE_STATIC_DECRYPTED,
            SAMPLE_CERT_DECRYPTED
        ])
        mock_nh.encrypt = MagicMock(side_effect=[
            b'encrypted_pubkey',
            b'encrypted_payload'
        ])
        # finish() fails
        mock_nh.finish = AsyncMock(side_effect=Exception("Finish failed"))

        # Mock verify_server_cert and get_client_payload
        with patch('pymeow.pymeow.handshake.verify_server_cert', MagicMock()):
            with patch('pymeow.pymeow.handshake.get_client_payload') as mock_get_payload:
                mock_payload = MagicMock()
                mock_payload.SerializeToString = MagicMock(return_value=b'client_payload')
                mock_get_payload.return_value = mock_payload

                # Call the function under test and expect HandshakeError
                with pytest.raises(HandshakeError, match="Failed to create noise socket"):
                    await do_handshake(mock_client, mock_fs, mock_ephemeral_kp)
