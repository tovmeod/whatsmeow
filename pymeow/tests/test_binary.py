"""Test binary protocol encoding and decoding."""
import pytest
from ..pymeow.binary.encoder import Encoder
from ..pymeow.binary.decoder import Decoder
from ..pymeow.generated.waMsgTransport import WAMsgTransport_pb2

@pytest.mark.asyncio
async def test_message_encode_decode():
    """Test encoding and decoding a message."""
    # Create a test message
    msg = WAMsgTransport_pb2.Message()
    msg.key.id = "test123"
    msg.key.remoteJid = "1234567890@s.whatsapp.net"
    msg.key.fromMe = True
    msg.conversation = "Hello, World!"

    # Create encoder/decoder pair
    enc_key = b"x" * 32  # Test key
    encoder = Encoder(enc_key=enc_key)
    decoder = Decoder(dec_key=enc_key)

    # Encode message
    encoded = encoder.encode_message(msg)
    assert encoded  # Should have data

    # Decode message
    decoded = decoder.decode_message(encoded)

    # Verify decoded message matches original
    assert decoded.key.id == msg.key.id
    assert decoded.key.remoteJid == msg.key.remoteJid
    assert decoded.key.fromMe == msg.key.fromMe
    assert decoded.conversation == msg.conversation
