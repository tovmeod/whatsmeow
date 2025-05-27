"""
Decoder for WhatsApp binary protocol.

Port of whatsmeow/binary/decoder.go
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..generated import WAMsgTransport_pb2

class Decoder:
    """Decodes binary format into protocol buffer messages."""

    def __init__(self, dec_key: bytes = b"", mac_key: bytes = b""):
        self.dec_key = dec_key
        self.mac_key = mac_key
        self.sequence_number = 0

    def decode_message(self, data: bytes) -> WAMsgTransport_pb2.MessageTransport:
        """Decode binary data into a protocol buffer message."""
        if self.dec_key:
            data = self._decrypt_payload(data)

        transport = WAMsgTransport_pb2.MessageTransport()
        transport.ParseFromString(self._decode_with_header(data))

        return transport.payload.applicationPayload

    def _decrypt_payload(self, data: bytes) -> bytes:
        if not self.dec_key:
            return data

        aesgcm = AESGCM(self.dec_key)
        nonce = struct.pack(">Q", self.sequence_number) + b"\x00\x00\x00\x00"
        self.sequence_number += 1

        return aesgcm.decrypt(nonce, data, None)

    def _decode_with_header(self, data: bytes) -> bytes:
        header_size = struct.calcsize(">I")
        size = struct.unpack(">I", data[:header_size])[0]
        return data[header_size:header_size + size]
