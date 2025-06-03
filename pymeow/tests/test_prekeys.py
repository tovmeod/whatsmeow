"""Test prekeys handling."""
import pytest
from datetime import datetime, timedelta
import struct
import os
from unittest.mock import MagicMock, AsyncMock, patch

from ..pymeow.prekeys import (
    PreKeyStore, PreKey, PreKeyBundle, PreKeyResp, PreKeyError,
    WANTED_PREKEY_COUNT, MIN_PREKEY_COUNT, DJB_TYPE,
    pre_key_to_node, pre_keys_to_nodes, node_to_pre_key, node_to_pre_key_bundle
)
from ..pymeow.binary.node import Node
from ..pymeow.util.keys.keypair import KeyPair
from ..pymeow.types import JID

def test_pre_key_constants():
    """Test that pre-key constants match Go implementation."""
    assert WANTED_PREKEY_COUNT == 50
    assert MIN_PREKEY_COUNT == 5
    assert DJB_TYPE == 5  # curve25519 key type

def test_key_pair_creation():
    """Test KeyPair creation with public key only."""
    pub_key = b'\x01' * 32

    # Test creating with public key only
    key_pair = KeyPair.from_public_key(pub_key)
    assert key_pair.pub == pub_key
    assert key_pair.priv is None

    # Test creating full key pair
    priv_key = b'\x02' * 32
    key_pair = KeyPair(pub=pub_key, priv=priv_key)
    assert key_pair.pub == pub_key
    assert key_pair.priv == priv_key

def test_pre_key_creation():
    """Test PreKey creation and properties."""
    # Generate a new PreKey
    pre_key = PreKey.generate(key_id=123)

    assert pre_key.key_id == 123
    assert len(pre_key.pub) == 32
    assert len(pre_key.priv) == 32
    assert pre_key.signature is None

    # Test with public key only
    pub_key = b'\x03' * 32
    key_pair = KeyPair.from_public_key(pub_key)
    pre_key = PreKey(key_pair=key_pair, key_id=456, signature=b'\x04' * 64)

    assert pre_key.key_id == 456
    assert pre_key.pub == pub_key
    assert pre_key.priv is None
    assert pre_key.signature == b'\x04' * 64

def test_pre_key_to_node():
    """Test converting PreKey to Node."""
    # Test unsigned pre-key
    pre_key = PreKey.generate(key_id=123)
    node = pre_key_to_node(pre_key)

    assert node.tag == "key"
    assert len(node.content) == 2

    # Check ID encoding (3 bytes from 4-byte big-endian)
    id_node = node.content[0]
    assert id_node.tag == "id"
    assert len(id_node.content) == 3
    assert struct.unpack(">I", b'\x00' + id_node.content)[0] == 123

    # Check value
    value_node = node.content[1]
    assert value_node.tag == "value"
    assert value_node.content == pre_key.pub

    # Test signed pre-key
    pre_key.signature = b'\x05' * 64
    node = pre_key_to_node(pre_key)

    assert node.tag == "skey"
    assert len(node.content) == 3

    sig_node = node.content[2]
    assert sig_node.tag == "signature"
    assert sig_node.content == pre_key.signature

def test_pre_keys_to_nodes():
    """Test converting list of PreKeys to nodes."""
    pre_keys = [PreKey.generate(i) for i in range(1, 4)]
    nodes = pre_keys_to_nodes(pre_keys)

    assert len(nodes) == 3
    for i, node in enumerate(nodes):
        assert node.tag == "key"
        # Verify the key ID is encoded correctly
        id_node = node.content[0]
        key_id = struct.unpack(">I", b'\x00' + id_node.content)[0]
        assert key_id == i + 1

def test_node_to_pre_key():
    """Test parsing PreKey from Node."""
    # Create test node for unsigned pre-key
    key_id = 123
    pub_key = b'\x06' * 32

    node = Node(
        tag="key",
        content=[
            Node(tag="id", content=struct.pack(">I", key_id)[1:]),  # 3 bytes
            Node(tag="value", content=pub_key)
        ]
    )

    pre_key = node_to_pre_key(node)
    assert pre_key.key_id == key_id
    assert pre_key.pub == pub_key
    assert pre_key.priv is None
    assert pre_key.signature is None

    # Test signed pre-key
    signature = b'\x07' * 64
    signed_node = Node(
        tag="skey",
        content=[
            Node(tag="id", content=struct.pack(">I", key_id)[1:]),
            Node(tag="value", content=pub_key),
            Node(tag="signature", content=signature)
        ]
    )

    signed_pre_key = node_to_pre_key(signed_node)
    assert signed_pre_key.key_id == key_id
    assert signed_pre_key.pub == pub_key
    assert signed_pre_key.priv is None
    assert signed_pre_key.signature == signature

def test_node_to_pre_key_errors():
    """Test error handling in node_to_pre_key."""
    # Missing ID tag
    with pytest.raises(PreKeyError, match="prekey node doesn't contain ID tag"):
        node = Node(tag="key", content=[
            Node(tag="value", content=b'\x08' * 32)
        ])
        node_to_pre_key(node)

    # Invalid ID length
    with pytest.raises(PreKeyError, match="prekey ID has unexpected number of bytes"):
        node = Node(tag="key", content=[
            Node(tag="id", content=b'\x01\x02'),  # Only 2 bytes
            Node(tag="value", content=b'\x08' * 32)
        ])
        node_to_pre_key(node)

    # Missing value tag
    with pytest.raises(PreKeyError, match="prekey node doesn't contain value tag"):
        node = Node(tag="key", content=[
            Node(tag="id", content=b'\x01\x02\x03')
        ])
        node_to_pre_key(node)

    # Invalid public key length
    with pytest.raises(PreKeyError, match="prekey value has unexpected number of bytes"):
        node = Node(tag="key", content=[
            Node(tag="id", content=b'\x01\x02\x03'),
            Node(tag="value", content=b'\x08' * 16)  # Wrong length
        ])
        node_to_pre_key(node)

    # Missing signature in signed pre-key
    with pytest.raises(PreKeyError, match="signed prekey node doesn't contain signature tag"):
        node = Node(tag="skey", content=[
            Node(tag="id", content=b'\x01\x02\x03'),
            Node(tag="value", content=b'\x08' * 32)
        ])
        node_to_pre_key(node)

def test_pre_key_bundle():
    """Test PreKeyBundle creation and validation."""
    pre_key = PreKey.generate(123)
    signed_pre_key = PreKey.generate(456)
    signed_pre_key.signature = b'\x09' * 64

    bundle = PreKeyBundle(
        registration_id=12345,
        device_id=1,
        pre_key=pre_key,
        signed_pre_key=signed_pre_key,
        identity_key=b'\x0a' * 32
    )

    assert bundle.registration_id == 12345
    assert bundle.device_id == 1
    assert bundle.pre_key == pre_key
    assert bundle.signed_pre_key == signed_pre_key
    assert bundle.identity_key == b'\x0a' * 32

def test_node_to_pre_key_bundle():
    """Test parsing PreKeyBundle from Node."""
    # Create test bundle node
    registration_id = 12345
    device_id = 1
    identity_key = b'\x0b' * 32

    # Create pre-key and signed pre-key nodes
    pre_key_node = Node(tag="key", content=[
        Node(tag="id", content=struct.pack(">I", 123)[1:]),
        Node(tag="value", content=b'\x0c' * 32)
    ])

    signed_pre_key_node = Node(tag="skey", content=[
        Node(tag="id", content=struct.pack(">I", 456)[1:]),
        Node(tag="value", content=b'\x0d' * 32),
        Node(tag="signature", content=b'\x0e' * 64)
    ])

    bundle_node = Node(
        tag="bundle",
        content=[
            Node(tag="registration", content=struct.pack(">I", registration_id)),
            Node(tag="identity", content=identity_key),
            pre_key_node,
            signed_pre_key_node
        ]
    )

    bundle = node_to_pre_key_bundle(device_id, bundle_node)

    assert bundle.registration_id == registration_id
    assert bundle.device_id == device_id
    assert bundle.pre_key is not None
    assert bundle.pre_key.key_id == 123
    assert bundle.signed_pre_key is not None
    assert bundle.signed_pre_key.key_id == 456
    assert bundle.signed_pre_key.signature == b'\x0e' * 64
    assert bundle.identity_key == identity_key

def test_node_to_pre_key_bundle_errors():
    """Test error handling in node_to_pre_key_bundle."""
    # Test with error node
    error_node = Node(tag="bundle", content=[
        Node(tag="error", content="Test error")
    ])

    with pytest.raises(PreKeyError, match="got error getting prekeys"):
        node_to_pre_key_bundle(1, error_node)

    # Missing registration
    with pytest.raises(PreKeyError, match="invalid registration ID"):
        node = Node(tag="bundle", content=[
            Node(tag="identity", content=b'\x0f' * 32)
        ])
        node_to_pre_key_bundle(1, node)

    # Invalid registration ID
    with pytest.raises(PreKeyError, match="invalid registration ID"):
        node = Node(tag="bundle", content=[
            Node(tag="registration", content=b'\x01\x02\x03'),  # Wrong length
            Node(tag="identity", content=b'\x0f' * 32)
        ])
        node_to_pre_key_bundle(1, node)

    # Missing identity key
    with pytest.raises(PreKeyError, match="invalid identity key"):
        node = Node(tag="bundle", content=[
            Node(tag="registration", content=struct.pack(">I", 12345))
        ])
        node_to_pre_key_bundle(1, node)

    # Missing signed pre-key - the function tries to parse whatever node it finds as a pre-key
    # Since there's no proper "key" node, it will try to parse the bundle node itself
    with pytest.raises(PreKeyError, match="prekey node doesn't contain ID tag"):
        node = Node(tag="bundle", content=[
            Node(tag="registration", content=struct.pack(">I", 12345)),
            Node(tag="identity", content=b'\x0f' * 32),
            # No skey node here
        ])
        node_to_pre_key_bundle(1, node)

def test_pre_key_resp():
    """Test PreKeyResp structure."""
    # Success case
    bundle = PreKeyBundle(
        registration_id=12345,
        device_id=1,
        pre_key=None,
        signed_pre_key=PreKey.generate(123),
        identity_key=b'\x10' * 32
    )

    resp = PreKeyResp(bundle=bundle, error=None)
    assert resp.bundle == bundle
    assert resp.error is None

    # Error case
    error = PreKeyError("Test error")
    resp = PreKeyResp(bundle=None, error=error)
    assert resp.bundle is None
    assert resp.error == error

@pytest.mark.asyncio
async def test_pre_key_store():
    """Test PreKeyStore functionality."""
    store = PreKeyStore()

    # Test initial state
    assert store._next_pre_key_id == 1
    assert len(store._pre_keys) == 0
    assert len(store._uploaded_keys) == 0

    # Test key generation
    keys = await store.get_or_gen_pre_keys(wanted_count=10)
    assert len(keys) == 10

    # All keys should have unique IDs
    key_ids = [key.key_id for key in keys]
    assert len(set(key_ids)) == 10

    # Keys should be sequential
    assert key_ids == list(range(1, 11))

@pytest.mark.asyncio
async def test_pre_key_store_upload_marking():
    """Test marking pre-keys as uploaded."""
    store = PreKeyStore()

    # Generate some keys
    keys = await store.get_or_gen_pre_keys(wanted_count=5)
    assert all(key_id not in store._uploaded_keys for key_id in [key.key_id for key in keys])

    # Mark up to key ID 3 as uploaded
    await store.mark_pre_keys_as_uploaded(3)

    # Keys 1, 2, 3 should be marked as uploaded
    assert 1 in store._uploaded_keys
    assert 2 in store._uploaded_keys
    assert 3 in store._uploaded_keys
    assert 4 not in store._uploaded_keys
    assert 5 not in store._uploaded_keys

@pytest.mark.asyncio
async def test_pre_key_store_key_exhaustion():
    """Test pre-key ID exhaustion."""
    store = PreKeyStore()
    store._next_pre_key_id = 0xFFFFFF - 1  # Near the limit

    # Generate keys up to the limit
    keys = await store._generate_pre_keys(2)
    assert len(keys) == 2
    assert keys[0].key_id == 0xFFFFFF - 1
    assert keys[1].key_id == 0xFFFFFF

    # Should not generate more keys beyond the limit
    more_keys = await store._generate_pre_keys(1)
    assert len(more_keys) == 0

def test_key_pair_signing():
    """Test KeyPair signing functionality."""
    # Test with full key pair
    signing_key = KeyPair.generate()
    target_key = KeyPair.generate()

    # Should be able to sign
    signature = signing_key.sign(target_key)
    assert len(signature) == 64

    # Test with public-key-only KeyPair
    pub_only_key = KeyPair.from_public_key(b'\x11' * 32)

    # Should raise error when trying to sign
    with pytest.raises(ValueError, match="Cannot sign with a public-key-only KeyPair"):
        pub_only_key.sign(target_key)

    # Should raise error when trying to create signed pre-key
    with pytest.raises(ValueError, match="Cannot sign with a public-key-only KeyPair"):
        pub_only_key.create_signed_pre_key(123)

def test_serialization_roundtrip():
    """Test that pre-key serialization and deserialization work correctly."""
    # Create original pre-key
    original = PreKey.generate(key_id=789)
    original.signature = b'\x12' * 64

    # Convert to node
    node = pre_key_to_node(original)

    # Convert back to pre-key
    deserialized = node_to_pre_key(node)

    # Should have same public data
    assert deserialized.key_id == original.key_id
    assert deserialized.pub == original.pub
    assert deserialized.signature == original.signature

    # Private key should not be included in serialization
    assert deserialized.priv is None

@pytest.mark.asyncio
async def test_client_integration_methods():
    """Test client integration methods with mocking."""
    from unittest.mock import MagicMock, AsyncMock

    # Mock client
    mock_client = MagicMock()
    mock_client.send_iq = AsyncMock()
    mock_client.server_jid = "server@whatsapp.net"
    mock_client.upload_prekeys_lock = AsyncMock().__aenter__()
    mock_client.last_pre_key_upload = None
    mock_client.store = MagicMock()
    mock_client.store.registration_id = 12345
    mock_client.store.identity_key = MagicMock()
    mock_client.store.identity_key.pub = b'\x13' * 32
    mock_client.store.signed_pre_key = PreKey.generate(999)
    mock_client.store.signed_pre_key.signature = b'\x14' * 64
    mock_client.store.pre_keys = PreKeyStore()
    mock_client.send_log = MagicMock()

    # Mock successful response for get_server_prekey_count
    from ..pymeow.prekeys import get_server_prekey_count

    mock_response = MagicMock()
    mock_count_node = MagicMock()
    mock_count_node.attrs = {"value": "25"}
    mock_response.get_child_by_tag.return_value = mock_count_node
    mock_client.send_iq.return_value = (mock_response, None)

    # Test get_server_prekey_count
    count = await get_server_prekey_count(mock_client)
    assert count == 25

    # Test with missing value
    mock_count_node.attrs = {}
    with pytest.raises(PreKeyError, match="server response missing prekey count value"):
        await get_server_prekey_count(mock_client)

def test_jid_parsing():
    """Test JID parsing in fetch_pre_keys response."""
    # This would test the JID.from_string call in fetch_pre_keys
    # but requires proper JID implementation
    pass
