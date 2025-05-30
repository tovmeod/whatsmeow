"""
Tests for the FrameSocket implementation.

This tests the WebSocket framing and integration with NoiseSocket in legacy mode.
"""
import pytest
import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import WSMessage, WSMsgType, ClientWebSocketResponse

from ..pymeow.socket.framesocket import FrameSocket
from ..pymeow.socket.noisesocket import NoiseSocket

@pytest.mark.asyncio
async def test_framesocket_initialization():
    """Test initialization of FrameSocket."""
    fs = FrameSocket()

    # Check that the attributes are initialized correctly
    assert fs._ws is None
    assert fs._receive_handler is None
    assert fs._closed is True

    # Check that a NoiseSocket instance was created
    assert isinstance(fs.noise, NoiseSocket)

@pytest.mark.asyncio
async def test_connect():
    """Test connecting to a WebSocket server."""
    fs = FrameSocket()

    # Create a future for the ws_connect result
    connect_future = asyncio.Future()
    connect_future.set_result(MagicMock(spec=ClientWebSocketResponse))
    mock_ws = connect_future.result()

    # Create a future for the close result
    close_future = asyncio.Future()
    close_future.set_result(None)
    mock_ws.close = lambda: close_future

    # Create a mock session with synchronous methods that return futures
    mock_session = MagicMock()
    mock_session.ws_connect = lambda url: connect_future
    mock_session.close = lambda: close_future

    # Patch the ClientSession to return our mock
    with patch('aiohttp.ClientSession', return_value=mock_session), \
         patch.object(FrameSocket, '_receive_loop', return_value=None), \
         patch('asyncio.create_task') as mock_create_task:

        try:
            # Test connecting
            await fs.connect("wss://example.com")

            # Check that the WebSocket was stored
            assert fs._ws == mock_ws

            # Check that the closed flag was updated
            assert fs._closed is False

            # Check that the receive loop was started
            mock_create_task.assert_called_once()

            # Save the current call count
            call_count = mock_create_task.call_count

            # Test connecting when already connected
            await fs.connect("wss://example.com")

            # Check that the receive loop was not started again
            assert mock_create_task.call_count == call_count
        finally:
            # Ensure we close the session and WebSocket
            await fs.close()

@pytest.mark.asyncio
async def test_send_frame():
    """Test sending a frame through the WebSocket."""
    fs = FrameSocket()

    # Create a future for the send_bytes result
    send_future = asyncio.Future()
    send_future.set_result(None)

    # Mock the WebSocket with a synchronous send_bytes method that returns a future
    mock_ws = MagicMock(spec=ClientWebSocketResponse)
    mock_ws.send_bytes = lambda data: send_future
    fs._ws = mock_ws
    fs._closed = False

    # Mock the NoiseSocket.encrypt_frame method
    fs.noise.encrypt_frame = MagicMock(return_value=b'encrypted_data')

    # Test sending a frame
    await fs.send_frame(b'test_data')

    # Check that encrypt_frame was called with the correct data
    fs.noise.encrypt_frame.assert_called_once_with(b'test_data')

    # Test sending a frame when the WebSocket is closed
    fs._closed = True

    with pytest.raises(ConnectionError, match="WebSocket not connected"):
        await fs.send_frame(b'test_data')

    # Test sending a frame when the WebSocket is None
    fs._closed = False
    fs._ws = None

    with pytest.raises(ConnectionError, match="WebSocket not connected"):
        await fs.send_frame(b'test_data')

@pytest.mark.asyncio
async def test_receive_loop():
    """Test the receive loop for handling incoming WebSocket frames."""
    fs = FrameSocket()

    # Create futures for async operations
    close_future = asyncio.Future()
    close_future.set_result(None)

    # Mock the WebSocket with synchronous methods that return futures
    mock_ws = MagicMock(spec=ClientWebSocketResponse)
    mock_ws.close = lambda: close_future
    fs._ws = mock_ws
    fs._closed = False

    # Mock the NoiseSocket.decrypt_frame method
    fs.noise.decrypt_frame = MagicMock(return_value=b'decrypted_data')

    # Create a real async function for the handler
    async def handler(data):
        assert data == b'decrypted_data'
        return None

    fs._receive_handler = handler

    # Create a binary message
    binary_msg = MagicMock(spec=WSMessage)
    binary_msg.type = WSMsgType.BINARY
    binary_msg.data = b'encrypted_data'

    # Create a close message
    close_msg = MagicMock(spec=WSMessage)
    close_msg.type = WSMsgType.CLOSED

    # Mock the WebSocket.__aiter__ method to return our messages
    mock_ws.__aiter__.return_value = [binary_msg, close_msg]

    # Test the receive loop
    await fs._receive_loop()

    # Check that decrypt_frame was called with the correct data
    fs.noise.decrypt_frame.assert_called_once_with(b'encrypted_data')

    # Check that the WebSocket was closed
    assert fs._closed is True

    # Test the receive loop when the WebSocket is None
    fs._ws = None

    # This should return immediately without error
    await fs._receive_loop()

@pytest.mark.asyncio
async def test_on_frame():
    """Test setting the frame handler."""
    fs = FrameSocket()

    # Create a real async function instead of using AsyncMock
    async def handler(data):
        return None

    # Set the handler
    fs.on_frame(handler)

    # Check that the handler was set
    assert fs._receive_handler == handler

@pytest.mark.asyncio
async def test_close():
    """Test closing the WebSocket connection."""
    fs = FrameSocket()

    # Create a future for the close result
    close_future = asyncio.Future()
    close_future.set_result(None)

    # Mock the WebSocket with a synchronous close method that returns a future
    mock_ws = MagicMock(spec=ClientWebSocketResponse)
    mock_ws.close = lambda: close_future
    fs._ws = mock_ws
    fs._closed = False

    # Create a mock session with a synchronous close method that returns a future
    mock_session = MagicMock()
    mock_session.close = lambda: close_future
    fs._session = mock_session

    # Test closing
    await fs.close()

    # Check that the closed flag was updated
    assert fs._closed is True

    # Test closing when already closed
    await fs.close()

    # Test closing when the WebSocket is None
    fs._ws = None
    fs._closed = False

    # This should not raise an error
    await fs.close()

@pytest.mark.asyncio
async def test_integration_with_noisesocket():
    """Test the integration between FrameSocket and NoiseSocket in legacy mode."""
    fs = FrameSocket()

    # Create futures for async operations
    send_future = asyncio.Future()
    send_future.set_result(None)

    handler_future = asyncio.Future()
    handler_future.set_result(None)

    # Mock the WebSocket with synchronous methods that return futures
    mock_ws = MagicMock(spec=ClientWebSocketResponse)
    mock_ws.send_bytes = lambda data: send_future
    fs._ws = mock_ws
    fs._closed = False

    # Set up the NoiseSocket for testing
    fs.noise._handshake_complete = True

    # Test sending a frame
    test_data = b'test_data'
    encrypted_data = b'encrypted_data'
    fs.noise.encrypt_frame = MagicMock(return_value=encrypted_data)

    await fs.send_frame(test_data)

    # Check that encrypt_frame was called with the correct data
    fs.noise.encrypt_frame.assert_called_once_with(test_data)

    # Test receiving a frame
    received_data = b'received_data'
    decrypted_data = b'decrypted_data'
    fs.noise.decrypt_frame = MagicMock(return_value=decrypted_data)

    # Create a real async function for the handler
    async def handler(data):
        assert data == decrypted_data
        return None

    fs._receive_handler = handler

    # Create a binary message
    binary_msg = MagicMock(spec=WSMessage)
    binary_msg.type = WSMsgType.BINARY
    binary_msg.data = received_data

    # Mock the WebSocket.__aiter__ method to return our message
    mock_ws.__aiter__.return_value = [binary_msg]

    # Run the receive loop (it will exit after processing the message)
    with patch.object(fs, '_closed', side_effect=[False, True]):
        await fs._receive_loop()
