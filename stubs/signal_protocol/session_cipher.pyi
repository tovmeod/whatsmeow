from signal_protocol.address import ProtocolAddress
from signal_protocol.protocol import CiphertextMessage, PreKeySignalMessage, SignalMessage
from signal_protocol.storage import InMemSignalProtocolStore

# Module-level functions
def message_encrypt(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: bytes,
) -> CiphertextMessage: ...
def message_decrypt(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: CiphertextMessage,
) -> bytes: ...
def message_decrypt_prekey(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: PreKeySignalMessage,
) -> bytes: ...
def message_decrypt_signal(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: SignalMessage,
) -> bytes: ...
