"""
Tests for disappearing messages functionality in PyMeow.
"""
import logging
import unittest
from unittest.mock import MagicMock, AsyncMock
import asyncio
from collections import defaultdict # For _event_handlers

from pymeow.pymeow import ExpirationType
from pymeow.pymeow.client import Client # Using real Client
from pymeow.pymeow.protocol import ProtocolNode
from pymeow.pymeow.websocket import WebSocketClient # For spec of _websocket
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2

logger = logging.getLogger(__name__)

class TestDisappearingMessages(unittest.IsolatedAsyncioTestCase):
    """Test cases for disappearing messages functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = Client() # Instantiate real Client
        
        # Mock dependencies
        self.client._websocket = AsyncMock(spec=WebSocketClient)
        self.client._auth_state = MagicMock()
        self.client._auth_state.me = "self@s.whatsapp.net" # Example JID
        self.client._auth_state.device = MagicMock()
        self.client._auth_state.device.device_id = "TESTDEVICE"


        self.client._message_store = AsyncMock()
        self.client._event_handlers = defaultdict(list) # As in Client.__init__
        
        # Set client state
        self.client._is_connected = True
        self.client._is_authenticated = True
        
        # Mock methods that would lead to actual network calls or complex internal logic not being tested here
        self.client._send_iq_and_wait = AsyncMock()
        # For individual chat ephemeral settings (if sent as regular message)
        self.client._message_queue = MagicMock() 
        self.client._message_queue.put = AsyncMock()


    async def test_set_disappearing_messages_individual_chat(self):
        """Test setting disappearing messages for an individual chat."""
        chat_jid = "1234567890@s.whatsapp.net" # Individual JID
        duration = ExpirationType.ONE_DAY.value

        # The current Client.set_disappearing_messages sends a regular message
        # with a ProtocolMessage for individual chats.
        # This message gets put on the _message_queue.
        
        await self.client.set_disappearing_messages(
            chat_jid=chat_jid,
            duration_seconds=duration
        )

        self.client._message_queue.put.assert_awaited_once()
        args, _ = self.client._message_queue.put.call_args
        _, message_node_sent, _ = args[0] # id, node, future

        self.assertIsInstance(message_node_sent, ProtocolNode)
        self.assertEqual(message_node_sent.tag, "message")
        self.assertEqual(message_node_sent.attrs["to"], chat_jid)
        
        # Verify the content is a serialized Protobuf WAWebProtobufsE2E_pb2.Message
        # containing a ProtocolMessage for ephemeral setting.
        self.assertTrue(isinstance(message_node_sent.content, bytes))
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.ParseFromString(message_node_sent.content)

        self.assertTrue(proto_msg.HasField("protocol_message"))
        protocol_sub_msg = proto_msg.protocol_message
        self.assertEqual(protocol_sub_msg.type, WAWebProtobufsE2E_pb2.ProtocolMessage.Type.EPHEMERAL_SETTING)
        self.assertEqual(protocol_sub_msg.ephemeral_expiration, duration)
        self.assertTrue(protocol_sub_msg.ephemeral_setting_timestamp > 0)

    async def test_set_disappearing_messages_group_chat(self):
        """Test setting disappearing messages for a group chat."""
        group_jid = "group_id@g.us"
        duration = ExpirationType.ONE_WEEK.value

        # For group chats, set_disappearing_messages uses _send_iq_and_wait
        # to send a w:g2 iq stanza.
        self.client._send_iq_and_wait.return_value = ProtocolNode("iq", {"type": "result"}) # Simulate success

        await self.client.set_disappearing_messages(
            chat_jid=group_jid,
            duration_seconds=duration
        )

        self.client._send_iq_and_wait.assert_awaited_once()
        args, _ = self.client._send_iq_and_wait.call_args
        iq_node_sent = args[0] # First positional arg to _send_iq_and_wait
        
        self.assertEqual(iq_node_sent.tag, "iq")
        self.assertEqual(iq_node_sent.attrs["to"], group_jid)
        self.assertEqual(iq_node_sent.attrs["type"], "set")
        self.assertEqual(iq_node_sent.attrs["xmlns"], "w:g2") # Namespace for group operations

        disappearing_mode_node = iq_node_sent.content[0] # Assuming first child
        self.assertEqual(disappearing_mode_node.tag, "disappearing_mode")
        self.assertEqual(disappearing_mode_node.attrs["duration"], str(duration))
    
    async def test_set_90_day_disappearing_messages_group(self):
        """Test setting 90-day disappearing messages for a group chat."""
        group_jid = "another_group@g.us"
        duration = ExpirationType.NINETY_DAYS.value

        self.client._send_iq_and_wait.return_value = ProtocolNode("iq", {"type": "result"})

        await self.client.set_disappearing_messages(
            chat_jid=group_jid,
            duration_seconds=duration
        )
        
        self.client._send_iq_and_wait.assert_awaited_once()
        args, _ = self.client._send_iq_and_wait.call_args
        iq_node_sent = args[0]
        
        self.assertEqual(iq_node_sent.tag, "iq")
        self.assertEqual(iq_node_sent.attrs["to"], group_jid)
        self.assertEqual(iq_node_sent.attrs["xmlns"], "w:g2")
        disappearing_mode_node = iq_node_sent.content[0]
        self.assertEqual(disappearing_mode_node.tag, "disappearing_mode")
        self.assertEqual(disappearing_mode_node.attrs["duration"], str(duration))


    async def test_get_disappearing_messages_group_chat(self):
        """Test getting disappearing messages settings for a group chat."""
        group_jid = "group_id@g.us"
        expected_duration = ExpirationType.ONE_DAY.value

        # Prepare a mock server response for the IQ query
        mock_response_content = [
            ProtocolNode("disappearing_mode", {"duration": str(expected_duration)})
        ]
        mock_response_node = ProtocolNode("iq", {"type": "result"}, content=mock_response_content)
        self.client._send_iq_and_wait.return_value = mock_response_node

        settings = await self.client.get_disappearing_messages(group_jid)
        
        self.client._send_iq_and_wait.assert_awaited_once()
        args, _ = self.client._send_iq_and_wait.call_args
        iq_node_sent = args[0]

        self.assertEqual(iq_node_sent.tag, "iq")
        self.assertEqual(iq_node_sent.attrs["to"], group_jid)
        self.assertEqual(iq_node_sent.attrs["type"], "get")
        self.assertEqual(iq_node_sent.attrs["xmlns"], "w:g2") # Namespace for group operations
        self.assertEqual(iq_node_sent.content[0].tag, "disappearing_mode") # Check for query content
        
        self.assertTrue(settings['enabled'])
        self.assertEqual(settings['duration_seconds'], expected_duration)
        self.assertFalse(settings['is_ephemeral']) # is_ephemeral is not part of group settings typically

    async def test_get_disappearing_messages_individual_chat_not_implemented(self):
        """Test getting disappearing messages for individual chat (currently not implemented in client)."""
        # Client.get_disappearing_messages seems designed for groups based on its IQ structure.
        # If it were to support individual chats, it would need a different mechanism.
        # For now, test that it might return default/off if called for individual.
        individual_jid = "1234567890@s.whatsapp.net"
        
        # If _send_iq_and_wait is called and fails or returns non-group-like structure:
        self.client._send_iq_and_wait.return_value = ProtocolNode("iq", {"type": "result"}, content=[]) # Empty result

        settings = await self.client.get_disappearing_messages(individual_jid)
        
        # Depending on implementation, this might raise error or return defaults
        # Current client.get_disappearing_messages uses group IQ. If it fails for individual,
        # it might return default (disabled) or error. Let's assume it returns disabled.
        self.assertFalse(settings['enabled'])
        self.assertEqual(settings['duration_seconds'], 0)
        self.assertFalse(settings['is_ephemeral'])


if __name__ == "__main__":
    unittest.main()
