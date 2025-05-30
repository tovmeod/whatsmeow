"""
WhatsApp prekeys handling.

Port of whatsmeow/prekeys.go
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
import os
import struct
import asyncio
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .exceptions import PreKeyError
from .binary.node import Node
from .types import JID

def pre_key_to_node(key: 'PreKeyData') -> Node:
    """Port of Go's preKeyToNode function.

    Convert a pre-key to a binary Node with proper key ID encoding.

    Args:
        key: The pre-key to convert

    Returns:
        Node: The converted node
    """
    # Encode key ID as 3-byte big-endian integer (matching Go's keyID[1:])
    key_id_bytes = struct.pack(">I", key.key_id)[1:]  # Skip first byte to get 3 bytes

    # Create the node with id and value child nodes
    node = Node(
        tag="key",
        content=[
            Node(tag="id", content=key_id_bytes),
            Node(tag="value", content=key.public_key),
        ]
    )

    # If this is a signed pre-key (has signature), use skey tag and add signature
    if hasattr(key, 'signature') and key.signature:
        node.tag = "skey"
        node.content.append(Node(tag="signature", content=key.signature))

    return node

def pre_keys_to_nodes(pre_keys: List['PreKeyData']) -> List[Node]:
    """Port of Go's preKeysToNodes function.

    Convert a list of pre-keys to a list of nodes.

    Args:
        pre_keys: List of pre-keys to convert

    Returns:
        List[Node]: List of converted nodes
    """
    return [pre_key_to_node(key) for key in pre_keys]

def node_to_pre_key(node: Node) -> Optional['PreKeyData']:
    """Port of Go's nodeToPreKey function.

    Parse a pre-key from a node.

    Args:
        node: The node to parse

    Returns:
        Optional[PreKeyData]: The parsed pre-key, or None if parsing failed
    """
    key = PreKeyData(
        key_id=0,
        public_key=None,
        private_key=None,
        uploaded=False
    )

    # Check for id tag
    id_node = None
    for child in node.content:
        if isinstance(child, Node) and child.tag == "id":
            id_node = child
            break

    if not id_node:
        return None

    # Parse key ID from id node
    try:
        if isinstance(id_node.content, bytes):
            # Key ID is a 3-byte big-endian integer, prepend a zero byte
            id_bytes = bytes([0]) + id_node.content
            if len(id_bytes) != 4:
                return None
            key.key_id = struct.unpack(">I", id_bytes)[0]
        else:
            return None
    except (ValueError, TypeError, struct.error):
        return None

    # Check for value tag
    value_node = None
    for child in node.content:
        if isinstance(child, Node) and child.tag == "value":
            value_node = child
            break

    if not value_node or not isinstance(value_node.content, bytes):
        return None

    # Parse public key
    public_key = value_node.content
    if len(public_key) != 32:
        return None

    key.public_key = public_key

    # If this is a signed pre-key, parse signature
    if node.tag == "skey":
        sig_node = None
        for child in node.content:
            if isinstance(child, Node) and child.tag == "signature":
                sig_node = child
                break

        if not sig_node or not isinstance(sig_node.content, bytes):
            return None

        signature = sig_node.content
        if len(signature) != 64:
            return None

        # For SignedPreKeyData, create that instead
        return SignedPreKeyData(
            key_id=key.key_id,
            public_key=key.public_key,
            private_key=None,
            signature=signature,
            timestamp=datetime.now()
        )

    return key

def node_to_pre_key_bundle(device_id: int, node: Node) -> Optional[PreKeyBundle]:
    """Port of Go's nodeToPreKeyBundle function.

    Parse a pre-key bundle from a node.

    Args:
        device_id: The device ID
        node: The node to parse

    Returns:
        Optional[PreKeyBundle]: The parsed pre-key bundle, or None if parsing failed

    Raises:
        PreKeyError: If there's an error in the node
    """
    # Check for error node
    for child in node.content:
        if isinstance(child, Node) and child.tag == "error":
            raise PreKeyError(f"Error in pre-key response: {child.xml_string()}")

    # Get registration node
    registration_node = None
    for child in node.content:
        if isinstance(child, Node) and child.tag == "registration":
            registration_node = child
            break

    if not registration_node or not isinstance(registration_node.content, bytes) or len(registration_node.content) != 4:
        raise PreKeyError("Invalid registration ID in pre-key response")

    registration_id = struct.unpack(">I", registration_node.content)[0]

    # Find keys node (might be directly in content or in a "keys" child node)
    keys_node = None
    for child in node.content:
        if isinstance(child, Node) and child.tag == "keys":
            keys_node = child
            break

    if not keys_node:
        keys_node = node

    # Get identity key
    identity_key_node = None
    for child in keys_node.content:
        if isinstance(child, Node) and child.tag == "identity":
            identity_key_node = child
            break

    if not identity_key_node or not isinstance(identity_key_node.content, bytes) or len(identity_key_node.content) != 32:
        raise PreKeyError("Invalid identity key in pre-key response")

    identity_key = identity_key_node.content

    # Get pre-key (optional)
    pre_key_node = None
    for child in keys_node.content:
        if isinstance(child, Node) and child.tag == "key":
            pre_key_node = child
            break

    pre_key = None
    if pre_key_node:
        pre_key = node_to_pre_key(pre_key_node)
        if not pre_key:
            raise PreKeyError("Invalid pre-key in pre-key response")

    # Get signed pre-key (required)
    signed_pre_key_node = None
    for child in keys_node.content:
        if isinstance(child, Node) and child.tag == "skey":
            signed_pre_key_node = child
            break

    if not signed_pre_key_node:
        raise PreKeyError("Missing signed pre-key in pre-key response")

    signed_pre_key = node_to_pre_key(signed_pre_key_node)
    if not signed_pre_key or not isinstance(signed_pre_key, SignedPreKeyData):
        raise PreKeyError("Invalid signed pre-key in pre-key response")

    # Create bundle
    return PreKeyBundle(
        registration_id=registration_id,
        device_id=device_id,
        pre_key=pre_key if isinstance(pre_key, PreKeyData) else None,
        signed_pre_key=signed_pre_key,
        identity_key=identity_key
    )

# Constants matching Go implementation
WANTED_PREKEY_COUNT = 50  # Number of prekeys to upload in a batch
MIN_PREKEY_COUNT = 5     # Threshold for when to upload new prekeys
DJB_TYPE = 5  # curve25519 key type (matching Go's ecc.DjbType)

@dataclass
class SignedPreKeyData:
    """Signed pre-key data structure."""
    key_id: int
    public_key: bytes
    private_key: bytes
    signature: bytes
    timestamp: datetime

    def to_node(self) -> Node:
        """Convert to binary node for server communication."""
        return Node(
            tag="skey",
            attributes={
                "id": str(self.key_id),
                "timestamp": str(int(self.timestamp.timestamp()))
            },
            content=[
                Node(tag="key", attributes={}, content=self.public_key),
                Node(tag="signature", attributes={}, content=self.signature)
            ]
        )

@dataclass
class PreKeyData:
    """Pre-key data structure matching libsignal's prekey."""
    key_id: int
    public_key: bytes
    private_key: bytes
    uploaded: bool = False

    def to_node(self) -> Node:
        """Convert to binary node for server communication."""
        return Node(
            tag="key",
            attributes={
                "id": str(self.key_id)
            },
            content=self.public_key
        )

@dataclass
class PreKeyResp:
    """Response structure for fetchPreKeys - matches Go's preKeyResp struct."""
    bundle: Optional[PreKeyBundle]
    error: Optional[Exception]

@dataclass
class PreKeyBundle:
    """Pre-key bundle for Signal protocol."""
    registration_id: int
    device_id: int
    pre_key: Optional[PreKeyData]
    signed_pre_key: SignedPreKeyData
    identity_key: bytes

class PreKeyStore:
    """Manages WhatsApp pre-keys."""

    def __init__(self):
        self._pre_keys: Dict[int, PreKeyData] = {}
        self._next_pre_key_id = 0
        self._last_upload: Optional[datetime] = None
        self.registration_id = struct.unpack(">I", os.urandom(4))[0]
        self._upload_lock = asyncio.Lock()
        self.signed_pre_key: Optional[SignedPreKeyData] = None
        self.identity_key: Optional[bytes] = None

    def can_upload(self) -> bool:
        """Implements whatsmeow.*Client.canUploadPreKeys.

        Check if we can upload pre-keys now based on the last upload time.

        Returns:
            bool: True if we can upload pre-keys, False if we've uploaded recently.
        """
        if self._last_upload is None:
            return True

        # Don't allow uploading more than once every 10 minutes
        min_upload_interval = timedelta(minutes=10)
        time_since_last_upload = datetime.now() - self._last_upload
        can_upload = time_since_last_upload >= min_upload_interval
        return can_upload

    async def get_or_gen_pre_keys(self, wanted_count: int = WANTED_PREKEY_COUNT) -> List[PreKeyData]:
        """Implements store.PreKeyStore.GetOrGenPreKeys.

        Get existing unuploaded pre-keys or generate new ones if needed.

        Args:
            wanted_count: Number of pre-keys to return.

        Returns:
            List of PreKeyData objects, which may include both existing unuploaded
            keys and newly generated ones.

        Raises:
            PreKeyError: If there's an error generating new keys.
        """
        # Get existing unuploaded keys
        existing = [k for k in self._pre_keys.values() if not k.uploaded]

        # If we don't have enough, generate more
        if len(existing) < wanted_count:
            # Generate the difference
            new_keys = self._generate_pre_keys(wanted_count - len(existing))
            if not new_keys and len(existing) < MIN_PREKEY_COUNT:
                raise PreKeyError("Failed to generate sufficient pre-keys")
            # Combine existing and new keys
            return existing + new_keys

        # If we have enough, return the requested number
        return existing[:wanted_count]

    def _generate_pre_keys(self, count: int = WANTED_PREKEY_COUNT) -> List[PreKeyData]:
        """Implements store.SQLStore.genOnePreKey.

        Generate a batch of pre-keys.

        Args:
            count: Number of pre-keys to generate.

        Returns:
            List of generated PreKeyData objects.
        """
        if len(self._pre_keys) >= WANTED_PREKEY_COUNT:
            return []

        # Don't generate more than the maximum allowed
        count = min(count, WANTED_PREKEY_COUNT - len(self._pre_keys))
        if count <= 0:
            return []


        keys = []
        for _ in range(count):
            # If we've reached the maximum key ID, stop generating more keys
            if self._next_pre_key_id > 0xFFFFFF:
                break

            key_id = self._next_pre_key_id
            self._next_pre_key_id += 1  # Don't wrap around to 0

            # Generate X25519 key pair
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            key = PreKeyData(
                key_id=key_id,
                private_key=private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ),
                public_key=public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
            self._pre_keys[key_id] = key
            keys.append(key)

        return keys

    async def mark_keys_as_uploaded(self, last_key_id: int) -> None:
        """Implements store.PreKeyStore.MarkPreKeysAsUploaded.

        Mark pre-keys as uploaded up to the specified ID.

        Args:
            last_key_id: The highest key ID to mark as uploaded.

        Note:
            This also updates the last upload timestamp to the current time.
        """
        # Update the last upload time first
        self._last_upload = datetime.now()

        # Mark all keys up to last_key_id as uploaded
        for key in self._pre_keys.values():
            if key.key_id <= last_key_id:
                key.uploaded = True


    async def generate_pre_key(self) -> PreKeyData:
        """Implements store.PreKeyStore.GenOnePreKey.

        Generate a single pre-key.

        Returns:
            PreKeyData: The generated pre-key

        Raises:
            RuntimeError: If the maximum pre-key ID has been reached
        """
        if self._next_pre_key_id > 0xFFFFFF:
            raise RuntimeError("reached maximum pre-key ID")

        key_id = self._next_pre_key_id
        self._next_pre_key_id += 1

        # Generate X25519 key pair
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        key = PreKeyData(
            key_id=key_id,
            private_key=private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            public_key=public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            uploaded=True  # Mark as uploaded by default to match Go behavior
        )

        # Store the key
        self._pre_keys[key_id] = key
        return key

    async def get_uploaded_count(self) -> int:
        """Implements store.PreKeyStore.UploadedPreKeyCount.

        Get the count of uploaded pre-keys.

        Returns:
            int: Number of pre-keys marked as uploaded
        """
        return sum(1 for key in self._pre_keys.values() if key.uploaded)

    async def mark_keys_as_uploaded(self, up_to_id: int) -> None:
        """Implements store.PreKeyStore.MarkPreKeysAsUploaded.

        Mark pre-keys as uploaded up to the specified ID.

        Args:
            up_to_id: The highest key ID to mark as uploaded

        Note:
            This also updates the last upload timestamp to now.
        """
        for key in self._pre_keys.values():
            if key.key_id <= up_to_id:
                key.uploaded = True

        # Update the last upload time
        self._last_upload = datetime.now()






    def get_pre_key(self, key_id: int) -> Optional[PreKeyData]:
        """Implements store.PreKeyStore.GetPreKey.

        Get a pre-key by ID.

        Args:
            key_id: The ID of the pre-key to retrieve.

        Returns:
            The requested PreKeyData or None if not found.
        """
        return self._pre_keys.get(key_id)

    async def remove_pre_key(self, key_id: int) -> None:
        """Implements store.PreKeyStore.RemovePreKey.

        Remove a pre-key from the store.

        Args:
            key_id: The ID of the pre-key to remove.

        Note:
            This is a no-op if the key doesn't exist.
        """
        self._pre_keys.pop(key_id, None)
