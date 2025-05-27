"""
Tests for the pymeow client.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from pymeow import Client
from ..pymeow.exceptions import PymeowError

@pytest.mark.asyncio
async def test_client_initialization():
    """Test that the client can be initialized."""
    client = Client()
    assert client is not None

@pytest.mark.asyncio
async def test_connect_disconnect():
    """Test connecting and disconnecting the client."""
    client = Client()

    # Test successful connection
    with patch('pymeow.client.Client._connect_ws') as mock_connect:
        await client.connect()
        mock_connect.assert_called_once()

    # Test disconnection
    with patch('pymeow.client.Client._disconnect_ws') as mock_disconnect:
        await client.disconnect()
        mock_disconnect.assert_called_once()

@pytest.mark.asyncio
async def test_event_handlers():
    """Test that event handlers are called correctly."""
    client = Client()

    # Mock event handler
    mock_handler = AsyncMock()
    client.on('message')(mock_handler)

    # Test event dispatching
    test_message = {"id": "123", "content": "test"}
    await client._dispatch_event('message', test_message)

    # Check that the handler was called with the correct arguments
    mock_handler.assert_awaited_once_with(test_message)

@pytest.mark.asyncio
async def test_send_message():
    """Test sending a message."""
    client = Client()

    # Mock the WebSocket send method
    with patch('pymeow.client.Client._send_ws') as mock_send:
        mock_send.return_value = {"id": "msg_123"}

        # Send a test message
        message_id = await client.send_message("1234567890@s.whatsapp.net", "Hello!")

        # Check that the message was sent with the correct parameters
        mock_send.assert_awaited_once()
        assert message_id == "msg_123"

@pytest.mark.asyncio
async def test_context_manager():
    """Test using the client as a context manager."""
    with patch('pymeow.client.Client.connect') as mock_connect, \
         patch('pymeow.client.Client.disconnect') as mock_disconnect:

        async with Client() as client:
            assert client is not None
            mock_connect.assert_awaited_once()

        # Check that disconnect was called when exiting the context
        mock_disconnect.assert_awaited_once()

@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in the client."""
    client = Client()

    # Mock a connection error
    with patch('pymeow.client.Client._connect_ws', side_effect=Exception("Connection failed")):
        with pytest.raises(PymeowError, match="Connection failed"):
            await client.connect()

    # Test that the error event is dispatched
    mock_handler = AsyncMock()
    client.on('error')(mock_handler)

    # Trigger an error
    await client._dispatch_event('error', "Test error")
    mock_handler.assert_awaited_once_with("Test error")
