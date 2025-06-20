from typing import Optional
from signal_protocol.address import ProtocolAddress
from signal_protocol.protocol import PreKeySignalMessage
from signal_protocol.state import PreKeyBundle, PreKeyId, SessionRecord
from signal_protocol.storage import InMemSignalProtocolStore

# Module-level functions
def process_prekey(
	message: PreKeySignalMessage,
	remote_address: ProtocolAddress,
	session_record: SessionRecord,
	protocol_store: InMemSignalProtocolStore,
) -> Optional[PreKeyId]: ...

def process_prekey_bundle(
	remote_address: ProtocolAddress,
	protocol_store: InMemSignalProtocolStore,
	bundle: PreKeyBundle,
) -> None: ...
