"""Test prekeys handling."""
import pytest
from datetime import datetime, timedelta
import struct
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from ..pymeow.prekeys import (
    PreKeyStore, PreKeyData, SignedPreKeyData, PreKeyBundle, PreKeyError,
    WANTED_PREKEY_COUNT, MIN_PREKEY_COUNT, DJB_TYPE
)
from ..pymeow.binary.node import Node

def test_pre_key_constants():
    """Test that pre-key constants match Go implementation."""
    assert WANTED_PREKEY_COUNT == 50
    assert MIN_PREKEY_COUNT == 5
    assert DJB_TYPE == 5  # curve25519 key type

def test_generate_pre_keys():
    """Test pre-key generation."""
    store = PreKeyStore()
    keys = store._generate_pre_keys()

    # Should generate WANTED_PREKEY_COUNT keys
    assert len(keys) == WANTED_PREKEY_COUNT

    # Each key should have unique ID and key material
    key_ids = set(key.key_id for key in keys)
    public_keys = set(key.public_key for key in keys)
    private_keys = set(key.private_key for key in keys)

    assert len(key_ids) == WANTED_PREKEY_COUNT
    assert len(public_keys) == WANTED_PREKEY_COUNT
    assert len(private_keys) == WANTED_PREKEY_COUNT

def test_x25519_key_generation():
    """Test that generated keys are valid X25519 keys."""
    store = PreKeyStore()
    keys = store._generate_pre_keys(count=1)
    key = keys[0]

    # Verify key lengths
    assert len(key.private_key) == 32
    assert len(key.public_key) == 32

    # Verify we can load them as X25519 keys
    try:
        x25519.X25519PrivateKey.from_private_bytes(key.private_key)
        x25519.X25519PublicKey.from_public_bytes(key.public_key)
    except Exception as e:
        pytest.fail(f"Invalid X25519 keys: {e}")

def test_key_id_wraparound():
    """Test that key IDs properly wrap around at 0xFFFFFF."""
    store = PreKeyStore()
    store._next_pre_key_id = 0xFFFFFF - 2

    # Generate exactly 3 keys to test the wrap-around
    keys = store._generate_pre_keys(count=3)

    # Get the key IDs
    key_ids = [key.key_id for key in keys]
    # The key IDs should be [0xFFFFFF-2, 0xFFFFFF-1, 0xFFFFFF] since we don't wrap around to 0
    expected_ids = [0xFFFFFF - 2, 0xFFFFFF - 1, 0xFFFFFF]
    assert key_ids == expected_ids

def test_pre_key_storage():
    """Test storing and retrieving pre-keys."""
    store = PreKeyStore()
    keys = store._generate_pre_keys()
    first_key = keys[0]

@pytest.mark.asyncio
async def test_get_or_gen_pre_keys():
    """Test getting existing or generating new pre-keys."""
    store = PreKeyStore()

    # First call should generate new keys
    keys = await store.get_or_gen_pre_keys(wanted_count=10)
    assert len(keys) == 10
    assert all(not k.uploaded for k in keys)

    # Mark some as uploaded
    await store.mark_keys_as_uploaded(keys[4].key_id)

    # Should get remaining non-uploaded keys plus new ones
    more_keys = await store.get_or_gen_pre_keys(wanted_count=10)
    assert len(more_keys) == 10
    assert all(not k.uploaded for k in more_keys)

@pytest.mark.asyncio
async def test_upload_timing():
    """Test upload timing restrictions."""
    store = PreKeyStore()

    # Should be able to upload initially
    assert store.can_upload()

    # Mark some keys as uploaded
    keys = store._generate_pre_keys(count=5)
    await store.mark_keys_as_uploaded(keys[-1].key_id)

    # Should not be able to upload again immediately
    assert not store.can_upload()

    # Reset last upload time to simulate time passing
    store._last_upload = datetime.now() - timedelta(minutes=11)
    assert store.can_upload()

def test_registration_id():
    """Test registration ID generation."""
    store = PreKeyStore()
    assert isinstance(store.registration_id, int)
    assert 0 <= store.registration_id <= 0xFFFFFFFF
    # Registration ID should be exactly 4 bytes when packed
    packed = struct.pack(">I", store.registration_id)
    assert len(packed) == 4

@pytest.mark.asyncio
async def test_server_operations():
    """Test server-related operations raise appropriate errors."""
    store = PreKeyStore()

    # get_server_pre_key_count() should raise NotImplementedError
    with pytest.raises(NotImplementedError):
        await store._get_server_pre_key_count()

    # upload_pre_keys() should raise PreKeyError with a wrapped NotImplementedError
    with pytest.raises(PreKeyError) as exc_info:
        await store._upload_pre_keys()
    assert "Failed to get server pre-key count" in str(exc_info.value)

def test_pre_key_node_format():
    """Test pre-key binary node format matches Go implementation."""
    store = PreKeyStore()
    keys = store._generate_pre_keys(count=1)
    key = keys[0]

    node = key.to_node()
    assert isinstance(node, Node)
    assert node.tag == "key"
    assert node.attributes["id"] == str(key.key_id)
    assert node.content == key.public_key

def test_signed_pre_key_node_format():
    """Test signed pre-key binary node format matches Go implementation."""
    timestamp = datetime.now()
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    signed_key = SignedPreKeyData(
        key_id=1,
        private_key=private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key=public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        signature=b"test_signature",
        timestamp=timestamp
    )

    node = signed_key.to_node()
    assert isinstance(node, Node)
    assert node.tag == "skey"
    assert node.attributes["id"] == "1"
    assert node.attributes["timestamp"] == str(int(timestamp.timestamp()))

    # Check child nodes
    assert len(node.content) == 2
    key_node = node.content[0]
    sig_node = node.content[1]

    assert key_node.tag == "key"
    assert key_node.content == signed_key.public_key
    assert sig_node.tag == "signature"
    assert sig_node.content == signed_key.signature

@pytest.mark.asyncio
async def test_pre_key_bundle():
    """Test pre-key bundle creation and formatting."""
    store = PreKeyStore()
    keys = store._generate_pre_keys(count=1)

    # Create a signed pre-key for the bundle
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    signed_key = SignedPreKeyData(
        key_id=1,
        private_key=private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key=public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        signature=b"test_signature",
        timestamp=datetime.now()
    )

    # Create a bundle
    bundle = PreKeyBundle(
        registration_id=store.registration_id,
        device_id=1,
        pre_key=keys[0],
        signed_pre_key=signed_key,
        identity_key=os.urandom(32)  # Simulated identity key
    )

    # Verify bundle properties
    assert bundle.registration_id == store.registration_id
    assert bundle.device_id == 1
    assert bundle.pre_key == keys[0]
    assert bundle.signed_pre_key == signed_key
    assert len(bundle.identity_key) == 32  # X25519 key size

def test_signed_pre_key():
    """Test signed pre-key handling."""
    timestamp = datetime.now()

    # Generate proper X25519 keys
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Create signed pre-key data
    signed_key = SignedPreKeyData(
        key_id=1,
        private_key=private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key=public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        signature=b"test_signature",
        timestamp=timestamp
    )

    # Test node conversion
    node = signed_key.to_node()
    assert node.tag == "skey"
    assert node.attributes["id"] == "1"
    assert node.attributes["timestamp"] == str(int(timestamp.timestamp()))
    assert len(node.content) == 2
    assert node.content[0].tag == "key"
    assert node.content[1].tag == "signature"


@pytest.mark.asyncio
async def test_gen_one_pre_key():
    """Test generating a single pre-key."""
    store = PreKeyStore()

    # Generate a single pre-key
    key = await store.GenOnePreKey()

    # Should return a valid PreKeyData object
    assert isinstance(key, PreKeyData)
    assert isinstance(key.key_id, int)
    assert len(key.public_key) == 32
    assert len(key.private_key) == 32
    assert key.uploaded is True  # Should be marked as uploaded by default


@pytest.mark.asyncio
async def test_uploaded_pre_key_count():
    """Test counting uploaded pre-keys."""
    store = PreKeyStore()

    # Initially should be 0
    assert await store.UploadedPreKeyCount() == 0

    # Generate and mark some keys as uploaded
    keys = store._generate_pre_keys(count=5)
    for key in keys[:3]:  # Mark first 3 as uploaded
        key.uploaded = True

    # Should count only uploaded keys
    assert await store.UploadedPreKeyCount() == 3

    # Mark one more as uploaded
    keys[3].uploaded = True
    assert await store.UploadedPreKeyCount() == 4


@pytest.mark.asyncio
async def test_mark_pre_keys_as_uploaded():
    """Test marking pre-keys as uploaded."""
    store = PreKeyStore()

    # Generate some keys
    keys = store._generate_pre_keys(count=5)
    key_ids = [key.key_id for key in keys]

    # Mark up to the 3rd key as uploaded
    await store.MarkPreKeysAsUploaded(key_ids[2])

    # First 3 keys should be marked as uploaded, others not

    # Last upload time should be updated
    assert store._last_upload is not None

    # Should be able to upload again after cooldown
    store._last_upload = datetime.now() - timedelta(minutes=11)
    assert store.can_upload()


@pytest.mark.asyncio
async def test_pre_key_id_generation():
    """Test pre-key ID generation sequence."""
    store = PreKeyStore()

    # Generate some keys and verify ID sequence
    key1 = await store.GenOnePreKey()
    key2 = await store.GenOnePreKey()

    assert key2.key_id == key1.key_id + 1

    # Test ID wrap-around at 0xFFFFFF
    store._next_pre_key_id = 0xFFFFFF - 1
    key3 = await store.GenOnePreKey()
    key4 = await store.GenOnePreKey()

    assert key3.key_id == 0xFFFFFF - 1
    assert key4.key_id == 0xFFFFFF  # Should not wrap around to 0

    # Next key should fail due to ID exhaustion
    with pytest.raises(RuntimeError, match="reached maximum pre-key ID"):
        await store.GenOnePreKey()


def test_node_to_pre_key():
    """Test parsing a pre-key from a node."""
    from ..pymeow.binary.node import Node
    from ..pymeow.prekeys import PreKeyData
    
    store = PreKeyStore()
    
    # Test with valid node
    valid_node = Node(
        tag="key",
        attributes={"id": "123"},
        content=[
            Node(tag="id", attributes={}, content=b"123"),
            Node(tag="value", attributes={}, content=b"\x05" + b"\x00" * 32)
        ]
    )
    
    pre_key = store._node_to_pre_key(valid_node)
    assert isinstance(pre_key, PreKeyData)
    assert pre_key.key_id == 123
    assert len(pre_key.public_key) == 33
    assert pre_key.private_key is None
    assert not pre_key.uploaded
    
    # Test with invalid node (missing id)
    invalid_node = Node(
        tag="key",
        attributes={},
        content=[
            Node(tag="value", attributes={}, content=b"\x05" + b"\x00" * 32)
        ]
    )
    assert store._node_to_pre_key(invalid_node) is None
    
    # Test with invalid node (missing value)
    invalid_node = Node(
        tag="key",
        attributes={},
        content=[
            Node(tag="id", attributes={}, content=b"123")
        ]
    )
    assert store._node_to_pre_key(invalid_node) is None
    
    # Test with invalid public key length
    invalid_key_node = Node(
        tag="key",
        attributes={"id": "123"},
        content=[
            Node(tag="id", attributes={}, content=b"123"),
            Node(tag="value", attributes={}, content=b"too_short")
        ]
    )
    assert store._node_to_pre_key(invalid_key_node) is None
    
    # Test with non-node input
    assert store._node_to_pre_key("not a node") is None
    assert store._node_to_pre_key(None) is None


def test_pre_key_serialization_roundtrip():
    """Test that pre-key can be serialized and deserialized correctly."""
    from ..pymeow.binary.node import Node
    
    store = PreKeyStore()
    
    # Generate a test pre-key
    original_key = store._generate_pre_keys(count=1)[0]
    
    # Convert to node and back
    node = store._pre_key_to_node(original_key)
    deserialized_key = store._node_to_pre_key(node)
    
    # Should have same key ID and public key
    assert deserialized_key is not None
    assert deserialized_key.key_id == original_key.key_id
    assert deserialized_key.public_key == original_key.public_key
    
    # Private key should not be included in serialization
    assert deserialized_key.private_key is None
    
    # Upload status should be reset
    assert not deserialized_key.uploaded


def test_pre_key_bundle_validation():
    """Test validation of pre-key bundle fields."""
    from ..pymeow.binary.node import Node
    from ..pymeow.prekeys import PreKeyError
    
    store = PreKeyStore()
    
    # Create a minimal valid bundle
    def create_minimal_bundle():
        return Node(
            tag="bundle",
            attributes={"registration": "123", "device_id": "456"},
            content=[
                Node(tag="identity", attributes={}, content=b"\x05" + b"\x00" * 32),
                Node(tag="skey", 
                     attributes={"id": "789"},
                     content=[
                         Node(tag="key", attributes={}, content=b"\x05" + b"\x00" * 32),
                         Node(tag="signature", attributes={}, content=b"\x00" * 64)
                     ])
            ]
        )
    
    # Test missing required fields
    bundle = create_minimal_bundle()
    bundle.attributes.pop("registration")
    with pytest.raises(PreKeyError, match="missing registration"):
        store._parse_pre_key_bundle(bundle)
    
    # Test invalid key format
    bundle = create_minimal_bundle()
    # Find the identity node in the content
    for node in bundle.content:
        if node.tag == "identity":
            node.content = b"invalid"
            break
    with pytest.raises(PreKeyError, match="invalid identity key"):
        store._parse_pre_key_bundle(bundle)
    
    # Test invalid node type
    with pytest.raises(PreKeyError, match="Invalid node type"):
        store._parse_pre_key_bundle("not a node")
