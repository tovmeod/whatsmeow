"""Test message secret handling."""
import pytest
import os
from ..pymeow.msgsecret import (
    MessageSecretStore,
    MessageSecret,
    MsgSecretType,
    apply_bot_message_hkdf,
    generate_msg_secret_key
)

def test_msg_secret_types():
    """Test message secret type enumeration."""
    assert MsgSecretType.POLL_VOTE.value == "Poll Vote"
    assert MsgSecretType.REACTION.value == "Enc Reaction"
    assert MsgSecretType.BOT_MSG.value == "Bot Message"

def test_bot_message_hkdf():
    """Test HKDF application for bot messages."""
    secret = os.urandom(32)
    derived = apply_bot_message_hkdf(secret)
    assert len(derived) == 32
    assert derived != secret

def test_generate_msg_secret_key():
    """Test message secret key generation."""
    mod_type = MsgSecretType.REACTION
    mod_sender = "123@s.whatsapp.net"
    orig_msg_id = "some_message_id"
    orig_sender = "456@s.whatsapp.net"
    orig_secret = os.urandom(32)

    key, iv = generate_msg_secret_key(
        mod_type,
        mod_sender,
        orig_msg_id,
        orig_sender,
        orig_secret
    )

    assert len(key) == 32
    assert len(iv) == 16

    # Generate another key with same inputs
    key2, iv2 = generate_msg_secret_key(
        mod_type,
        mod_sender,
        orig_msg_id,
        orig_sender,
        orig_secret
    )

    # Keys should be same (deterministic), IVs should be different (random)
    assert key == key2
    assert iv != iv2

def test_store_and_get_secret():
    """Test storing and retrieving message secrets."""
    store = MessageSecretStore()
    chat_id = "123456789@s.whatsapp.net"
    secret = os.urandom(32)
    expiration = 1234567890

    # Store secret
    store.store_secret(chat_id, secret, expiration)

    # Retrieve secret
    retrieved = store.get_secret(chat_id)
    assert retrieved is not None
    assert retrieved.secret == secret
    assert retrieved.expiration == expiration

def test_encrypt_decrypt_message():
    """Test message encryption and decryption with secrets."""
    store = MessageSecretStore()
    chat_id = "123456789@s.whatsapp.net"
    secret = os.urandom(32)
    expiration = 1234567890

    # Store secret
    store.store_secret(chat_id, secret, expiration)

    # Test message
    original_message = b"Hello, World!"
    msg_type = MsgSecretType.REACTION
    sender = "sender@s.whatsapp.net"
    orig_msg_id = "original_msg_id"
    orig_sender = "original@s.whatsapp.net"

    # Encrypt
    encrypted = store.encrypt_message(
        chat_id,
        original_message,
        msg_type,
        sender,
        orig_msg_id,
        orig_sender
    )
    assert encrypted is not None
    assert encrypted != original_message

    # Decrypt
    decrypted = store.decrypt_message(
        chat_id,
        encrypted,
        msg_type,
        sender,
        orig_msg_id,
        orig_sender
    )
    assert decrypted == original_message

def test_missing_secret():
    """Test behavior with non-existent secrets."""
    store = MessageSecretStore()
    chat_id = "nonexistent@s.whatsapp.net"
    msg_type = MsgSecretType.REACTION
    sender = "sender@s.whatsapp.net"
    orig_msg_id = "msg_id"
    orig_sender = "orig@s.whatsapp.net"

    # Try to encrypt without secret
    assert store.encrypt_message(
        chat_id,
        b"test",
        msg_type,
        sender,
        orig_msg_id,
        orig_sender
    ) is None

    # Try to decrypt without secret
    assert store.decrypt_message(
        chat_id,
        b"x" * 32,
        msg_type,
        sender,
        orig_msg_id,
        orig_sender
    ) is None
