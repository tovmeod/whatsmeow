"""
WhatsApp message secret handling.

Port of whatsmeow/msgsecret.go
"""
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
import os

from .generated.waCommon import WACommon_pb2
from .generated.waE2E import WAWebProtobufsE2E_pb2
from .util.cbcutil import encrypt_cbc, decrypt_cbc
from .util.hkdfutil import expand_hmac

class MsgSecretType(str, Enum):
    """Types of message secrets."""
    POLL_VOTE = "Poll Vote"
    REACTION = "Enc Reaction"
    COMMENT = "Enc Comment"
    REPORT_TOKEN = "Report Token"
    EVENT_RESPONSE = "Event Response"
    EVENT_EDIT = "Event Edit"
    BOT_MSG = "Bot Message"

@dataclass
class MessageSecret:
    """Message secret data."""
    secret: bytes
    expiration: int

def apply_bot_message_hkdf(message_secret: bytes) -> bytes:
    """Apply HKDF for bot messages."""
    return expand_hmac(
        message_secret,
        MsgSecretType.BOT_MSG.value.encode(),
        32
    )

def generate_msg_secret_key(
    modification_type: MsgSecretType,
    modification_sender: str,
    orig_msg_id: str,
    orig_msg_sender: str,
    orig_msg_secret: bytes
) -> Tuple[bytes, bytes]:
    """Generate a message secret key."""
    # Create use case secret as in Go implementation
    use_case_secret = (
        orig_msg_id.encode() +
        orig_msg_sender.encode() +
        modification_sender.encode() +
        modification_type.value.encode()
    )

    # Derive keys using HKDF
    derived_key = expand_hmac(orig_msg_secret, use_case_secret, 32)
    iv = os.urandom(16)  # Generate random IV

    return derived_key, iv

class MessageSecretStore:
    """Handles message secret storage and encryption."""

    def __init__(self):
        self._secrets: Dict[str, MessageSecret] = {}

    def store_secret(self, chat_id: str, secret: bytes, expiration: int) -> None:
        """Store a message secret for a chat."""
        self._secrets[chat_id] = MessageSecret(secret=secret, expiration=expiration)

    def get_secret(self, chat_id: str) -> Optional[MessageSecret]:
        """Get a stored message secret."""
        return self._secrets.get(chat_id)

    def encrypt_message(
        self,
        chat_id: str,
        data: bytes,
        msg_type: MsgSecretType,
        sender: str,
        orig_msg_id: str,
        orig_sender: str
    ) -> Optional[bytes]:
        """Encrypt message data with stored secret."""
        secret = self.get_secret(chat_id)
        if not secret:
            return None

        key, iv = generate_msg_secret_key(
            msg_type,
            sender,
            orig_msg_id,
            orig_sender,
            secret.secret
        )

        return iv + encrypt_cbc(key, iv, data)

    def decrypt_message(
        self,
        chat_id: str,
        data: bytes,
        msg_type: MsgSecretType,
        sender: str,
        orig_msg_id: str,
        orig_sender: str
    ) -> Optional[bytes]:
        """Decrypt message data with stored secret."""
        secret = self.get_secret(chat_id)
        if not secret:
            return None

        iv = data[:16]
        ciphertext = data[16:]

        key, _ = generate_msg_secret_key(
            msg_type,
            sender,
            orig_msg_id,
            orig_sender,
            secret.secret
        )

        return decrypt_cbc(key, iv, ciphertext)
