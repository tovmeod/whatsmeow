"""
Encoder for WhatsApp binary protocol.

Port of whatsmeow/binary/encoder.go
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..generated import WAMsgTransport_pb2

class Encoder:
    """Encodes protocol buffer messages into binary format for WhatsApp Web."""

    def __init__(self, enc_key: bytes = b"", mac_key: bytes = b""):
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.sequence_number = 0

    def encode_message(self, message: WAMsgTransport_pb2.MessageTransport) -> bytes:
        """Encode a protocol buffer message into binary format."""
        transport = WAMsgTransport_pb2.MessageTransport()
        transport.payload.applicationPayload.CopyFrom(message)

        encoded = transport.SerializeToString()
        if self.enc_key:
            encoded = self._encrypt_payload(encoded)

        return self._encode_with_header(encoded)

    def _encrypt_payload(self, data: bytes) -> bytes:
        if not self.enc_key:
            return data

        aesgcm = AESGCM(self.enc_key)
        nonce = struct.pack(">Q", self.sequence_number) + b"\x00\x00\x00\x00"
        self.sequence_number += 1

        return aesgcm.encrypt(nonce, data, None)

    def _encode_with_header(self, data: bytes) -> bytes:
        header = struct.pack(">I", len(data))
        return header + data
