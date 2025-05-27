"""Test broadcast list handling."""
import pytest
from datetime import datetime
from pymeow.broadcast import BroadcastListHandler, BroadcastList
from pymeow.generated.waMsgTransport import WAMsgTransport_pb2

@pytest.mark.asyncio
async def test_broadcast_creation():
    """Test creating a broadcast list."""
    handler = BroadcastListHandler()
    name = "Test Broadcast"
    recipients = ["123@s.whatsapp.net", "456@s.whatsapp.net"]

    with pytest.raises(NotImplementedError):
        # Should raise until properly implemented
        await handler.create_list(name, recipients)

@pytest.mark.asyncio
async def test_broadcast_get_list():
    """Test retrieving broadcast list."""
    handler = BroadcastListHandler()
    list_id = "broadcast-123"

    # No list should exist yet
    result = await handler.get_list(list_id)
    assert result is None

@pytest.mark.asyncio
async def test_broadcast_message():
    """Test sending broadcast message."""
    handler = BroadcastListHandler()
    list_id = "broadcast-123"

    # Create a test message
    message = WAMsgTransport_pb2.Message()
    message.conversation = "Test broadcast message"

    with pytest.raises(NotImplementedError):
        # Should raise until properly implemented
        await handler.send_message(list_id, message)

@pytest.mark.asyncio
async def test_broadcast_recipients():
    """Test managing broadcast recipients."""
    handler = BroadcastListHandler()
    list_id = "broadcast-123"
    new_recipients = ["789@s.whatsapp.net"]

    with pytest.raises(NotImplementedError):
        await handler.add_recipients(list_id, new_recipients)

    with pytest.raises(NotImplementedError):
        await handler.remove_recipients(list_id, new_recipients)
