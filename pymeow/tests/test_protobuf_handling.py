import unittest
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
from pymeow.pymeow.generated_protos.waCommon import WACommon_pb2

class TestProtobufSerialization(unittest.TestCase):

    def test_text_message_serialization_deserialization(self):
        msg = WAWebProtobufsE2E_pb2.Message()
        msg.conversation = "hello world"
        
        serialized_msg = msg.SerializeToString()
        
        new_msg = WAWebProtobufsE2E_pb2.Message()
        new_msg.ParseFromString(serialized_msg)
        
        self.assertEqual(new_msg.conversation, "hello world")

    def test_message_with_context_info_serialization(self):
        msg = WAWebProtobufsE2E_pb2.Message()
        msg.context_info.stanza_id = "quoted_msg_abc"
        msg.context_info.participant = "participant@s.whatsapp.net"
        msg.context_info.mentioned_jid.extend(["mention1@s.whatsapp.net", "mention2@s.whatsapp.net"])
        msg.context_info.ephemeral_expiration = 86400
        
        serialized_msg = msg.SerializeToString()
        
        new_msg = WAWebProtobufsE2E_pb2.Message()
        new_msg.ParseFromString(serialized_msg)
        
        self.assertEqual(new_msg.context_info.stanza_id, "quoted_msg_abc")
        self.assertEqual(new_msg.context_info.participant, "participant@s.whatsapp.net")
        self.assertListEqual(list(new_msg.context_info.mentioned_jid), ["mention1@s.whatsapp.net", "mention2@s.whatsapp.net"])
        self.assertEqual(new_msg.context_info.ephemeral_expiration, 86400)

    def test_message_key_serialization(self):
        key = WACommon_pb2.MessageKey()
        key.id = "key_id_123"
        key.remote_jid = "remote@s.whatsapp.net"
        key.from_me = True
        key.participant = "participant@s.whatsapp.net"
        
        serialized_key = key.SerializeToString()
        
        new_key = WACommon_pb2.MessageKey()
        new_key.ParseFromString(serialized_key)
        
        self.assertEqual(new_key.id, "key_id_123")
        self.assertEqual(new_key.remote_jid, "remote@s.whatsapp.net")
        self.assertTrue(new_key.from_me)
        self.assertEqual(new_key.participant, "participant@s.whatsapp.net")

if __name__ == '__main__':
    unittest.main()
