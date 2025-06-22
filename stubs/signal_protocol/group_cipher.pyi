from signal_protocol.protocol import SenderKeyDistributionMessage
from signal_protocol.sender_keys import SenderKeyName
from signal_protocol.storage import InMemSignalProtocolStore

# Module-level functions
def group_encrypt(
    protocol_store: InMemSignalProtocolStore,
    sender_key_id: SenderKeyName,
    plaintext: bytes,
) -> bytes: ...
def group_decrypt(
    skm_bytes: bytes,
    protocol_store: InMemSignalProtocolStore,
    sender_key_id: SenderKeyName,
) -> bytes: ...
def process_sender_key_distribution_message(
    sender_key_name: SenderKeyName,
    skdm: SenderKeyDistributionMessage,
    protocol_store: InMemSignalProtocolStore,
) -> None: ...
def create_sender_key_distribution_message(
    sender_key_name: SenderKeyName,
    protocol_store: InMemSignalProtocolStore,
) -> SenderKeyDistributionMessage: ...
