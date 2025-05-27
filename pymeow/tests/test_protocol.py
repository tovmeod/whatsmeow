# pymeow/tests/test_protocol.py
import unittest
from pymeow.pymeow.protocol import ProtocolNode, ProtocolEncoder, ProtocolDecoder, MessageType

class TestProtocolNodeWithBytes(unittest.TestCase):

    def test_encode_decode_node_with_byte_content(self):
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()

        original_node = ProtocolNode(
            tag="message",
            attrs={"to": "user@s.whatsapp.net", "id": "123", "type": "text"},
            content=b"This is serialized protobuf bytes"
        )

        encoded_data = encoder.encode(original_node)
        self.assertIsInstance(encoded_data, bytes)

        decoded_node, _ = decoder._decode_node(encoded_data, 0) # Test internal method for directness here

        self.assertIsInstance(decoded_node, ProtocolNode)
        self.assertEqual(decoded_node.tag, "message")
        self.assertEqual(decoded_node.attrs["to"], "user@s.whatsapp.net")
        self.assertEqual(decoded_node.attrs["id"], "123")
        self.assertEqual(decoded_node.attrs["type"], "text")
        self.assertEqual(decoded_node.content, b"This is serialized protobuf bytes")

    def test_encode_decode_node_with_child_nodes_and_byte_content(self):
        # This test checks if a node can have attributes and EITHER byte content OR child nodes,
        # but usually not both directly as simple content.
        # However, the current ProtocolNode structure might allow a list of mixed types if not careful.
        # Let's test a more complex IQ-like structure which might have children.
        # If a message node has byte content, it usually doesn't also have complex children
        # representing that same content's structure.
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()

        # Simulating an IQ set with a child that might contain bytes (though less common for IQs)
        # More typically, an IQ's children would also be ProtocolNodes.
        # Let's test a child node that itself has byte content.
        child_with_bytes = ProtocolNode(tag="payload_data", content=b"binary_payload")
        parent_node = ProtocolNode(
            tag="iq",
            attrs={"type": "set", "id": "iq1"},
            content=[
                ProtocolNode(tag="query", attrs={"xmlns": "custom:ns"}),
                child_with_bytes
            ]
        )

        encoded_data = encoder.encode(parent_node)
        decoded_node, _ = decoder._decode_node(encoded_data, 0)

        self.assertEqual(decoded_node.tag, "iq")
        self.assertEqual(decoded_node.attrs["type"], "set")
        self.assertIsInstance(decoded_node.content, list)
        self.assertEqual(len(decoded_node.content), 2)
        
        query_node = decoded_node.content[0]
        self.assertEqual(query_node.tag, "query")
        self.assertEqual(query_node.attrs["xmlns"], "custom:ns")
        
        decoded_child_with_bytes = decoded_node.content[1]
        self.assertEqual(decoded_child_with_bytes.tag, "payload_data")
        self.assertEqual(decoded_child_with_bytes.content, b"binary_payload")

    def test_encode_decode_node_no_content(self):
        encoder = ProtocolEncoder()
        decoder = ProtocolDecoder()
        original_node = ProtocolNode(tag="presence", attrs={"type": "available"})
        
        encoded_data = encoder.encode(original_node)
        decoded_node, _ = decoder._decode_node(encoded_data, 0)
        
        self.assertEqual(decoded_node.tag, "presence")
        self.assertEqual(decoded_node.attrs["type"], "available")
        self.assertIsNone(decoded_node.content) # Or empty list depending on how decoder handles it

    # Optional: Add a test that verifies the exact byte output for a simple node
    # This would require knowing the exact binary format, including type tags for strings, lists, etc.
    # For example:
    # def test_specific_byte_output_for_text_node(self):
    #     encoder = ProtocolEncoder()
    #     node = ProtocolNode(tag="message", attrs={"to": "jid"}, content="text")
    #     # Assume MessageType.ENCODED_STRING is 0x01, length prefixes, etc.
    #     # expected_bytes = b"..." # Construct the known expected byte string
    #     # self.assertEqual(encoder.encode(node), expected_bytes)


if __name__ == '__main__':
    unittest.main()
