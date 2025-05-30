"""
Tests for the NoiseSocket implementation.

This tests both the legacy mode (used by FrameSocket) and the direct mode
of the NoiseSocket class.
"""
import pytest
import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..pymeow.socket.noisesocket import NoiseSocket, new_noise_socket
from ..pymeow.binary.encoder import Encoder
from ..pymeow.binary.decoder import Decoder

@pytest.mark.asyncio
async def test_generate_iv():
    """Test the generate_iv static method."""
    # Test with counter 0
    iv_0 = NoiseSocket.generate_iv(0)
    assert len(iv_0) == 12
    assert iv_0[8:] == b'\x00\x00\x00\x00'

    # Test with counter 1
    iv_1 = NoiseSocket.generate_iv(1)
    assert len(iv_1) == 12
    assert iv_1[8:] == b'\x00\x00\x00\x01'

    # Test with a large counter
    iv_large = NoiseSocket.generate_iv(0x12345678)
    assert len(iv_large) == 12
    assert iv_large[8:] == b'\x12\x34\x56\x78'

@pytest.mark.asyncio
async def test_legacy_mode_initialization():
    """Test initialization in legacy mode (used by FrameSocket)."""
    ns = NoiseSocket()

    # Check that the legacy mode attributes are initialized
    assert isinstance(ns.encoder, Encoder)
    assert isinstance(ns.decoder, Decoder)
    assert ns._handshake_complete is False

    # Check that direct mode attributes are None or default values
    assert ns.fs is None
    assert ns.write_key is None
    assert ns.read_key is None
    assert ns.on_frame is None
    assert ns.write_counter == 0
    assert ns.read_counter == 0
    assert ns.write_lock is None
    assert ns.destroyed is False
    assert ns.stop_consumer is None

@pytest.mark.asyncio
async def test_direct_mode_initialization():
    """Test initialization in direct mode."""
    # Create mocks for the dependencies
    mock_fs = MagicMock()
    mock_write_key = MagicMock(spec=AESGCM)
    mock_read_key = MagicMock(spec=AESGCM)

    # Create a real async function for the frame handler
    async def frame_handler(data):
        return None

    # Initialize NoiseSocket in direct mode
    ns = NoiseSocket(
        fs=mock_fs,
        write_key=mock_write_key,
        read_key=mock_read_key,
        frame_handler=frame_handler
    )

    # Check that the direct mode attributes are initialized
    assert ns.fs == mock_fs
    assert ns.write_key == mock_write_key
    assert ns.read_key == mock_read_key
    assert ns.on_frame == frame_handler
    assert ns.write_counter == 0
    assert ns.read_counter == 0
    assert ns.write_lock is not None
    assert ns.destroyed is False
    assert ns.stop_consumer is not None

    # Check that the frame handler was set up
    mock_fs.on_frame.assert_called_once_with(ns._receive_encrypted_frame)

@pytest.mark.asyncio
async def test_legacy_encrypt_decrypt():
    """Test encrypt_frame and decrypt_frame methods in legacy mode."""
    ns = NoiseSocket()

    # Mock the handshake completion
    ns._handshake_complete = True

    # Mock the encoder and decoder
    ns.encoder.encode_message = MagicMock(return_value=b'encrypted_data')
    ns.decoder.decode_message = MagicMock(return_value=b'decrypted_data')

    # Test encrypt_frame
    encrypted = ns.encrypt_frame(b'test_data')
    assert encrypted == b'encrypted_data'
    ns.encoder.encode_message.assert_called_once_with(b'test_data')

    # Test decrypt_frame
    decrypted = ns.decrypt_frame(b'encrypted_data')
    assert decrypted == b'decrypted_data'
    ns.decoder.decode_message.assert_called_once_with(b'encrypted_data')

    # Test error when handshake is not complete
    ns._handshake_complete = False
    with pytest.raises(RuntimeError, match="Handshake not complete"):
        ns.encrypt_frame(b'test_data')

    with pytest.raises(RuntimeError, match="Handshake not complete"):
        ns.decrypt_frame(b'encrypted_data')

@pytest.mark.asyncio
async def test_direct_send_frame():
    """Test send_frame method in direct mode."""
    # Create futures for async operations
    send_future = asyncio.Future()
    send_future.set_result(None)

    # Create mocks for the dependencies
    mock_fs = MagicMock()
    mock_fs.send_frame = lambda data: send_future
    mock_write_key = MagicMock(spec=AESGCM)
    mock_write_key.encrypt = MagicMock(return_value=b'encrypted_data')
    mock_read_key = MagicMock(spec=AESGCM)

    # Create a real async function for the frame handler
    async def frame_handler(data):
        return None

    # Initialize NoiseSocket in direct mode
    ns = NoiseSocket(
        fs=mock_fs,
        write_key=mock_write_key,
        read_key=mock_read_key,
        frame_handler=frame_handler
    )

    # Test send_frame
    await ns.send_frame(b'test_data')

    # Check that the write key was used to encrypt the data
    mock_write_key.encrypt.assert_called_once()
    args, kwargs = mock_write_key.encrypt.call_args
    assert args[1] == b'test_data'  # Check plaintext
    assert kwargs == {}  # Check associated data

    # Check that the write counter was incremented
    assert ns.write_counter == 1

    # Test error when FrameSocket is not provided
    ns.fs = None
    with pytest.raises(RuntimeError, match="NoiseSocket not initialized with FrameSocket"):
        await ns.send_frame(b'test_data')

@pytest.mark.asyncio
async def test_direct_receive_encrypted_frame():
    """Test _receive_encrypted_frame method in direct mode."""
    # Create mocks for the dependencies
    mock_fs = MagicMock()
    mock_write_key = MagicMock(spec=AESGCM)
    mock_read_key = MagicMock(spec=AESGCM)
    mock_read_key.decrypt = MagicMock(return_value=b'decrypted_data')

    # Create a real async function for the frame handler
    handler_called = False

    async def frame_handler(data):
        nonlocal handler_called
        assert data == b'decrypted_data'
        handler_called = True
        return None

    # Initialize NoiseSocket in direct mode
    ns = NoiseSocket(
        fs=mock_fs,
        write_key=mock_write_key,
        read_key=mock_read_key,
        frame_handler=frame_handler
    )

    # Test _receive_encrypted_frame
    await ns._receive_encrypted_frame(b'encrypted_data')

    # Check that the read key was used to decrypt the data
    mock_read_key.decrypt.assert_called_once()
    args, kwargs = mock_read_key.decrypt.call_args
    assert args[1] == b'encrypted_data'  # Check ciphertext
    assert kwargs == {}  # Check associated data

    # Check that the frame handler was called
    assert handler_called is True

    # Check that the read counter was incremented
    assert ns.read_counter == 1

    # Test error handling
    mock_read_key.decrypt.side_effect = Exception("Decryption failed")

    # This should not raise an exception
    await ns._receive_encrypted_frame(b'bad_data')

    # Check that the read counter was incremented again
    assert ns.read_counter == 2

@pytest.mark.asyncio
async def test_is_connected():
    """Test is_connected method."""
    # Test with no FrameSocket
    ns = NoiseSocket()
    assert ns.is_connected() is False

    # Test with connected FrameSocket
    mock_fs = MagicMock()
    mock_fs._closed = False
    ns.fs = mock_fs
    assert ns.is_connected() is True

    # Test with disconnected FrameSocket
    mock_fs._closed = True
    assert ns.is_connected() is False

@pytest.mark.asyncio
async def test_stop():
    """Test stop method."""
    # Create mocks for the dependencies
    mock_fs = MagicMock()
    mock_fs.close = AsyncMock()
    mock_write_key = MagicMock(spec=AESGCM)
    mock_read_key = MagicMock(spec=AESGCM)
    mock_frame_handler = AsyncMock()

    # Initialize NoiseSocket in direct mode
    ns = NoiseSocket(
        fs=mock_fs,
        write_key=mock_write_key,
        read_key=mock_read_key,
        frame_handler=mock_frame_handler
    )

    # Test stop with disconnect=True
    await ns.stop(disconnect=True)

    # Check that the socket was marked as destroyed
    assert ns.destroyed is True

    # Check that the stop_consumer event was set
    assert ns.stop_consumer.is_set() is True

    # Check that the FrameSocket was closed
    mock_fs.close.assert_awaited_once()

    # Reset mocks
    mock_fs.close.reset_mock()
    ns.destroyed = False
    ns.stop_consumer.clear()

    # Test stop with disconnect=False
    await ns.stop(disconnect=False)

    # Check that the socket was marked as destroyed
    assert ns.destroyed is True

    # Check that the stop_consumer event was set
    assert ns.stop_consumer.is_set() is True

    # Check that the FrameSocket was not closed
    mock_fs.close.assert_not_awaited()

    # Test stop when already destroyed
    mock_fs.close.reset_mock()
    await ns.stop(disconnect=True)

    # Check that the FrameSocket was not closed again
    mock_fs.close.assert_not_awaited()

@pytest.mark.asyncio
async def test_new_noise_socket():
    """Test new_noise_socket function."""
    # Create mocks for the dependencies
    mock_fs = MagicMock()
    mock_write_key = MagicMock(spec=AESGCM)
    mock_read_key = MagicMock(spec=AESGCM)
    mock_frame_handler = AsyncMock()
    mock_disconnect_handler = AsyncMock()

    # Call new_noise_socket
    ns = new_noise_socket(
        fs=mock_fs,
        write_key=mock_write_key,
        read_key=mock_read_key,
        frame_handler=mock_frame_handler,
        disconnect_handler=mock_disconnect_handler
    )

    # Check that a NoiseSocket instance was returned
    assert isinstance(ns, NoiseSocket)

    # Check that the NoiseSocket was initialized with the correct parameters
    assert ns.fs == mock_fs
    assert ns.write_key == mock_write_key
    assert ns.read_key == mock_read_key
    assert ns.on_frame == mock_frame_handler
