"""
Tests for disappearing messages functionality in PyMeow.
"""
import logging
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio

from pymeow.pymeow import MessageUtils, ExpirationType
from pymeow.pymeow.client import Client
from pymeow.pymeow.protocol import ProtocolNode

logger = logging.getLogger(__name__)

class TestDisappearingMessages(unittest.IsolatedAsyncioTestCase):
    """Test cases for disappearing messages functionality."""

    def setUp(self):
        """Set up test fixtures."""
        print("[0] Setting up test")
        
        # Create a mock client with required attributes
        self.client = MagicMock(spec=Client)
        self.client._enqueue_message = AsyncMock()
        self.client._send_iq_and_wait = AsyncMock()
        self.client.logger = logging.getLogger(__name__)
        
        # Mock the message store
        self.client._message_store = AsyncMock()
        self.client._message_store.get_message = AsyncMock(return_value=None)
        
        # Mock the message queue
        self.client._message_queue = MagicMock()
        self.client._message_queue.put = AsyncMock()
        
        # Set up mock connection state
        self.client.connected = True
        self.client.logged_in = True
        self.client.is_connected = MagicMock(return_value=True)
        self.client._is_connected = True
        self.client._is_authenticated = True
        
        print("[0] Test setup complete")

    async def test_send_disappearing_message_90_days(self):
        """Test sending a disappearing message with 90-day expiration."""
        print("\n[1] Starting test_send_disappearing_message_90_days")
        
        # Configure the mock client's send_message method
        self.client.send_message = AsyncMock(return_value="3EB01234567890")
        
        # Call the method with the 90-day expiration
        try:
            result = await self.client.send_message(
                to="1234567890@s.whatsapp.net",
                content="Test disappearing message with 90-day expiration",
                expiration_seconds=ExpirationType.NINETY_DAYS.value
            )
            
            # Verify the message was sent with the correct parameters
            self.client.send_message.assert_called_once_with(
                to="1234567890@s.whatsapp.net",
                content="Test disappearing message with 90-day expiration",
                expiration_seconds=ExpirationType.NINETY_DAYS.value
            )
            
            # Verify the message ID was returned
            self.assertTrue(result.startswith('3EB0'), "Should return a valid message ID")
            
        except Exception as e:
            self.fail(f"Unexpected exception: {e}")
    
    async def test_set_90_day_disappearing_messages(self):
        """Test setting 90-day disappearing messages for a chat."""
        print("\n[2] Starting test_set_90_day_disappearing_messages")
        
        # Configure the mock client's set_disappearing_messages method
        expected_result = {
            'status': 'success',
            'duration_seconds': ExpirationType.NINETY_DAYS.value,
            'enabled': True
        }
        self.client.set_disappearing_messages = AsyncMock(return_value=expected_result)
        
        # Call the method with 90-day expiration
        result = await self.client.set_disappearing_messages(
            chat_jid="1234567890@s.whatsapp.net",
            duration_seconds=ExpirationType.NINETY_DAYS.value
        )
        
        # Verify the result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['duration_seconds'], ExpirationType.NINETY_DAYS.value)
        self.assertTrue(result['enabled'])
        
        # Verify the method was called with the correct parameters
        self.client.set_disappearing_messages.assert_called_once_with(
            chat_jid="1234567890@s.whatsapp.net",
            duration_seconds=ExpirationType.NINETY_DAYS.value
        )

    async def test_set_disappearing_messages(self):
        """Test setting disappearing messages for a chat."""
        # Configure the mock client's set_disappearing_messages method
        duration = ExpirationType.ONE_DAY.value
        expected_result = {
            'status': 'success',
            'duration_seconds': duration,
            'enabled': True
        }
        self.client.set_disappearing_messages = AsyncMock(return_value=expected_result)

        # Set disappearing messages for a chat
        result = await self.client.set_disappearing_messages(
            chat_jid="1234567890@s.whatsapp.net",
            duration_seconds=duration
        )

        # Verify the result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['duration_seconds'], duration)
        self.assertTrue(result['enabled'])
        
        # Verify the method was called with the correct parameters
        self.client.set_disappearing_messages.assert_called_once_with(
            chat_jid="1234567890@s.whatsapp.net",
            duration_seconds=duration
        )

    async def test_get_disappearing_messages(self):
        """Test getting disappearing messages settings for a chat."""
        # Configure the mock client's get_disappearing_messages method
        expected_settings = {
            'duration_seconds': 86400,
            'is_ephemeral': False,
            'enabled': True
        }
        self.client.get_disappearing_messages = AsyncMock(return_value=expected_settings)

        # Get disappearing messages settings
        settings = await self.client.get_disappearing_messages("1234567890@s.whatsapp.net")
        
        # Verify the result
        self.assertEqual(settings['duration_seconds'], 86400)
        self.assertFalse(settings['is_ephemeral'])
        self.assertTrue(settings['enabled'])
        
        # Verify the method was called with the correct parameters
        self.client.get_disappearing_messages.assert_called_once_with("1234567890@s.whatsapp.net")

        # Verify the settings
        self.assertTrue(settings['enabled'])
        self.assertEqual(settings['duration_seconds'], 86400)  # Raw value from the mock

class TestMessageUtils(unittest.TestCase):
    """Test cases for MessageUtils class."""

    def test_validate_duration(self):
        """Test duration validation."""
        self.assertTrue(MessageUtils.validate_duration(0))  # Off
        self.assertTrue(MessageUtils.validate_duration(86400))  # 1 day
        self.assertTrue(MessageUtils.validate_duration(604800))  # 1 week
        self.assertTrue(MessageUtils.validate_duration(7776000))  # 90 days
        self.assertFalse(MessageUtils.validate_duration(12345))  # Invalid duration

    def test_create_text_message_node_with_expiration(self):
        """Test creating a message node with expiration."""
        # Create a message with a valid expiration duration
        duration_seconds = 86400  # 1 day in seconds
        node = MessageUtils.create_text_message_node(
            to="1234567890@s.whatsapp.net",
            content="Test message",
            message_id="test123",
            expiration_seconds=duration_seconds
        )

        # Check the node attributes
        self.assertEqual(node.attrs['to'], '1234567890@s.whatsapp.net')

        # Check that the ephemeral node was added with the correct duration
        ephemeral_nodes = [
            child for child in getattr(node, 'content', [])
            if hasattr(child, 'tag') and child.tag == 'ephemeral'
        ]

        self.assertTrue(len(ephemeral_nodes) > 0, "No ephemeral node found in message content")
        ephemeral_node = ephemeral_nodes[0]
        self.assertEqual(ephemeral_node.attrs.get('duration'), str(duration_seconds))

    def test_create_ephemeral_message_node(self):
        """Test creating an ephemeral (view-once) message node."""
        node = MessageUtils.create_text_message_node(
            to="1234567890@s.whatsapp.net",
            content="Test view-once message",
            message_id="test456",
            is_ephemeral=True
        )

        self.assertEqual(node.attrs.get('ephemeral'), '1')


if __name__ == "__main__":
    import sys
    
    # Enable debug logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )
    
    # Run the specific test directly
    test = TestDisappearingMessages('test_send_disappearing_message')
    test.setUp()
    
    # Run the test with debug info
    print("\n=== Starting test with debug output ===\n")
    try:
        import asyncio
        asyncio.run(test.test_send_disappearing_message())
        print("\n=== Test completed successfully ===\n")
    except Exception as e:
        print(f"\n=== Test failed with error: {e} ===\n")
        raise
