import unittest
from datetime import datetime
from pymeow.pymeow.message_utils import MessageUtils, ExpirationType # Added ExpirationType
from pymeow.pymeow.protocol import ProtocolNode 
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
# from pymeow.pymeow.types.jid import JID # Not strictly needed if using string JIDs as per current MessageUtils

class TestMessageUtils(unittest.TestCase):

    def test_validate_duration(self):
        """Test duration validation (moved from test_disappearing_messages.py)."""
        self.assertTrue(MessageUtils.validate_duration(0))  # Off
        self.assertTrue(MessageUtils.validate_duration(ExpirationType.ONE_DAY.value))
        self.assertTrue(MessageUtils.validate_duration(ExpirationType.ONE_WEEK.value))
        self.assertTrue(MessageUtils.validate_duration(ExpirationType.NINETY_DAYS.value))
        self.assertFalse(MessageUtils.validate_duration(12345))  # Invalid duration

    def test_create_text_message_node_basic(self):
        recipient_jid_str = "recipient@s.whatsapp.net"
        msg_content = "Hello Protobuf!"
        msg_id = "test_msg_001"
        
        node = MessageUtils.create_text_message_node(recipient_jid_str, msg_content, msg_id)

        self.assertIsInstance(node, ProtocolNode)
        self.assertEqual(node.tag, "message")
        self.assertEqual(node.attrs["id"], msg_id)
        self.assertEqual(node.attrs["to"], recipient_jid_str)
        self.assertEqual(node.attrs["type"], "text")
        self.assertTrue(isinstance(node.content, bytes))

        # Deserialize and check protobuf content
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.ParseFromString(node.content)
        self.assertEqual(proto_msg.conversation, msg_content)

    def test_create_text_message_node_with_quote_mentions(self):
        recipient_jid_str = "recipient@s.whatsapp.net"
        msg_id = "test_msg_002"
        quoted_id = "quoted_abc"
        mentions_list = ["mention1@s.whatsapp.net", "mention2@s.whatsapp.net"]

        node = MessageUtils.create_text_message_node(
            recipient_jid_str, "Reply with mentions", msg_id,
            quoted_message_id=quoted_id,
            mentions=mentions_list
        )
        self.assertTrue(isinstance(node.content, bytes))
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.ParseFromString(node.content)

        self.assertEqual(proto_msg.context_info.stanza_id, quoted_id)
        self.assertListEqual(list(proto_msg.context_info.mentioned_jid), mentions_list)

    def test_create_text_message_node_disappearing_ephemeral(self):
        recipient_jid_str = "recipient@s.whatsapp.net"
        msg_id = "test_msg_003"
        expiration = ExpirationType.ONE_DAY.value # 1 day

        # Test disappearing message (sets fields in ContextInfo)
        node_disappearing = MessageUtils.create_text_message_node(
            recipient_jid_str, "This will disappear", msg_id + "_d",
            expiration_seconds=expiration
        )
        self.assertTrue(isinstance(node_disappearing.content, bytes))
        proto_msg_disappearing = WAWebProtobufsE2E_pb2.Message()
        proto_msg_disappearing.ParseFromString(node_disappearing.content)
        self.assertEqual(proto_msg_disappearing.context_info.ephemeral_expiration, expiration)
        self.assertTrue(proto_msg_disappearing.context_info.ephemeral_setting_timestamp > 0)

        # Test view-once (ephemeral attribute on ProtocolNode)
        node_ephemeral = MessageUtils.create_text_message_node(
            recipient_jid_str, "View this once", msg_id + "_e",
            is_ephemeral=True
        )
        self.assertEqual(node_ephemeral.attrs.get("ephemeral"), "1")
        self.assertTrue(isinstance(node_ephemeral.content, bytes))
        proto_msg_ephemeral = WAWebProtobufsE2E_pb2.Message()
        proto_msg_ephemeral.ParseFromString(node_ephemeral.content)
        self.assertEqual(proto_msg_ephemeral.conversation, "View this once")

    # The following tests were moved from test_disappearing_messages.py
    # and adapted for the new Protobuf structure.
    
    def test_create_text_message_node_with_expiration_moved(self):
        """Test creating a message node with expiration (adapted from moved test)."""
        duration_seconds = ExpirationType.ONE_DAY.value
        node = MessageUtils.create_text_message_node(
            to="1234567890@s.whatsapp.net",
            content="Test message",
            message_id="test123_moved",
            expiration_seconds=duration_seconds
        )

        self.assertEqual(node.attrs['to'], '1234567890@s.whatsapp.net')
        self.assertTrue(isinstance(node.content, bytes))
        
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.ParseFromString(node.content)
        
        self.assertEqual(proto_msg.context_info.ephemeral_expiration, duration_seconds)
        self.assertTrue(proto_msg.context_info.ephemeral_setting_timestamp > 0)


    def test_create_ephemeral_message_node_moved(self):
        """Test creating an ephemeral (view-once) message node (adapted from moved test)."""
        node = MessageUtils.create_text_message_node(
            to="1234567890@s.whatsapp.net",
            content="Test view-once message",
            message_id="test456_moved",
            is_ephemeral=True
        )

        self.assertEqual(node.attrs.get('ephemeral'), '1')
        self.assertTrue(isinstance(node.content, bytes))
        proto_msg = WAWebProtobufsE2E_pb2.Message()
        proto_msg.ParseFromString(node.content)
        self.assertEqual(proto_msg.conversation, "Test view-once message")
        # Check that ephemeral_expiration is NOT set for view-once by default
        self.assertEqual(proto_msg.context_info.ephemeral_expiration, 0)


if __name__ == '__main__':
    unittest.main()
