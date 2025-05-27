"""
Signal protocol store implementation for WhatsApp.

Port of whatsmeow/store/signal.go
"""
from typing import Optional, Dict, List
from dataclasses import dataclass
import json

from ..generated.waE2E import WAWebProtobufsE2E_pb2

@dataclass
class SignalSession:
    """Signal protocol session data."""
    registration_id: int
    identity_key_pair: bytes
    signed_pre_key: bytes
    signed_pre_key_id: int
    signed_pre_key_signature: bytes

class SignalStore:
    """Stores Signal protocol related data."""

    def __init__(self):
        self._sessions: Dict[str, bytes] = {}
        self._pre_keys: Dict[int, bytes] = {}
        self._sender_keys: Dict[str, bytes] = {}
        self._identity_keys: Dict[str, bytes] = {}
        self._registration_id: Optional[int] = None

    def get_session(self, jid: str) -> Optional[bytes]:
        """Get a Signal session for a JID."""
        return self._sessions.get(jid)

    def save_session(self, jid: str, session_data: bytes) -> None:
        """Save a Signal session for a JID."""
        self._sessions[jid] = session_data

    def get_pre_key(self, key_id: int) -> Optional[bytes]:
        """Get a pre-key by ID."""
        return self._pre_keys.get(key_id)

    def save_pre_key(self, key_id: int, key_data: bytes) -> None:
        """Save a pre-key."""
        self._pre_keys[key_id] = key_data

    def get_sender_key(self, group_id: str, sender_id: str) -> Optional[bytes]:
        """Get a sender key for a group participant."""
        key = f"{group_id}:{sender_id}"
        return self._sender_keys.get(key)

    def save_sender_key(self, group_id: str, sender_id: str, key_data: bytes) -> None:
        """Save a sender key for a group participant."""
        key = f"{group_id}:{sender_id}"
        self._sender_keys[key] = key_data

    def get_identity_key(self, jid: str) -> Optional[bytes]:
        """Get an identity key for a JID."""
        return self._identity_keys.get(jid)

    def save_identity_key(self, jid: str, key_data: bytes) -> None:
        """Save an identity key for a JID."""
        self._identity_keys[jid] = key_data

    def get_registration_id(self) -> Optional[int]:
        """Get the registration ID."""
        return self._registration_id

    def set_registration_id(self, reg_id: int) -> None:
        """Set the registration ID."""
        self._registration_id = reg_id
