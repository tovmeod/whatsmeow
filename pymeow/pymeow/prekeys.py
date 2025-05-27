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

    async def _get_server_pre_key_count(self) -> int:
        """Implements whatsmeow.*Client.getServerPreKeyCount.

        Get the current count of pre-keys on the server.

        Returns:
            int: Number of pre-keys on the server.

        Raises:
            PreKeyError: If there's an error communicating with the server.
        """
        # This will be implemented by the Client class to match sendIQ in Go
        raise NotImplementedError("Server communication not implemented")

    async def _upload_pre_keys(self) -> None:
        """Implements whatsmeow.*Client.uploadPreKeys.

        Upload pre-keys to the server with proper locking and rate limiting.

        Raises:
            PreKeyError: If there's an error during the upload process.
        """
        async with self._upload_lock:
            # Check upload cooldown
            if not self.can_upload():
                return

            # Check if we already have enough keys on the server
            try:
                server_count = await self._get_server_pre_key_count()
                if server_count >= WANTED_PREKEY_COUNT:
                    return
            except Exception as e:
                raise PreKeyError(f"Failed to get server pre-key count: {e}") from e

            # Get or generate pre-keys to upload
            keys = await self.get_or_gen_pre_keys(WANTED_PREKEY_COUNT)
            if not keys:
                raise PreKeyError("No pre-keys available for upload")

            # Convert to nodes for the server
            key_nodes = [self._pre_key_to_node(key) for key in keys]

            # This would be implemented by the Client class
            # await self._send_pre_key_upload_request(key_nodes)

            # Mark the keys as uploaded
            await self.mark_keys_as_uploaded(keys[-1].key_id)

    async def GenOnePreKey(self) -> PreKeyData:
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

    async def UploadedPreKeyCount(self) -> int:
        """Implements store.PreKeyStore.UploadedPreKeyCount.

        Get the count of uploaded pre-keys.

        Returns:
            int: Number of pre-keys marked as uploaded
        """
        return sum(1 for key in self._pre_keys.values() if key.uploaded)

    async def MarkPreKeysAsUploaded(self, up_to_id: int) -> None:
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

    def _pre_key_to_node(self, pre_key: PreKeyData) -> Node:
        """Implements preKeyToNode from prekeys.go.

        Convert a pre-key to a node for server communication.

        Args:
            pre_key: The pre-key to convert.
        Returns:
            Node: The converted node.
        """
        import logging
        logging.basicConfig(level=logging.DEBUG)
        logging.debug(f"_pre_key_to_node: key_id={pre_key.key_id}, public_key={pre_key.public_key.hex() if pre_key.public_key else None}")
        
        node = Node(
            tag="key",
            attributes={"id": str(pre_key.key_id)},
            content=pre_key.public_key
        )
        logging.debug(f"_pre_key_to_node: created node: {node}")
        return node

    def _node_to_pre_key(self, node: Node) -> Optional[PreKeyData]:
        """Implements nodeToPreKey from prekeys.go.

        Parse a single pre-key from a node.

        Args:
            node: The node containing the pre-key data.

        Returns:
            PreKeyData if the node contains valid pre-key data, None otherwise.
        """
        import logging
        logging.basicConfig(level=logging.DEBUG)
        logging.debug(f"_node_to_pre_key: node={node}")
        
        if not isinstance(node, Node) or not hasattr(node, 'content'):
            logging.debug("_node_to_pre_key: invalid node type or missing content")
            return None

        key_id = None
        public_key = None

        # Log the node structure for debugging
        logging.debug(f"_node_to_pre_key: node.tag={node.tag}")
        logging.debug(f"_node_to_pre_key: node.attributes={getattr(node, 'attributes', None)}")
        logging.debug(f"_node_to_pre_key: node.content type={type(node.content)}")
        if isinstance(node.content, bytes):
            logging.debug(f"_node_to_pre_key: node.content length={len(node.content)}")
        elif isinstance(node.content, list):
            logging.debug(f"_node_to_pre_key: node.content length={len(node.content)}")
            for i, item in enumerate(node.content):
                logging.debug(f"_node_to_pre_key: node.content[{i}] type={type(item)}")
                if isinstance(item, Node):
                    logging.debug(f"_node_to_pre_key:   tag={item.tag}, attrs={getattr(item, 'attributes', None)}")

        # Handle the node structure used in _pre_key_to_node (direct key node with id attribute and bytes content)
        if node.tag == "key" and hasattr(node, 'attributes') and 'id' in node.attributes:
            try:
                key_id = int(node.attributes['id'])
                if isinstance(node.content, bytes):
                    public_key = node.content
                    logging.debug(f"_node_to_pre_key: found key_id={key_id} in attributes, public_key length={len(public_key) if public_key else 0}")
                # Also handle the case where content is a list with a single bytes element
                elif isinstance(node.content, list) and len(node.content) == 1 and isinstance(node.content[0], bytes):
                    public_key = node.content[0]
                    logging.debug(f"_node_to_pre_key: found key_id={key_id} in attributes, public_key in list length={len(public_key) if public_key else 0}")
            except (ValueError, TypeError) as e:
                logging.debug(f"_node_to_pre_key: error parsing key_id: {e}")
                return None
        
        # Handle the case where the node has child nodes (id and value nodes)
        if public_key is None and isinstance(node.content, list):
            logging.debug("_node_to_pre_key: checking child nodes")
            for child in node.content:
                if not isinstance(child, Node):
                    continue
                    
                if child.tag == "id":
                    try:
                        if child.content is not None:
                            key_id = int(child.content)
                            logging.debug(f"_node_to_pre_key: found key_id={key_id} in id node")
                    except (ValueError, TypeError) as e:
                        logging.debug(f"_node_to_pre_key: error parsing key_id from id node: {e}")
                        return None
                elif child.tag == "value" and isinstance(child.content, bytes):
                    public_key = child.content
                    logging.debug(f"_node_to_pre_key: found public_key length={len(public_key) if public_key else 0} in value node")
        
        # If we have an attributes dict, check for id there too
        if key_id is None and hasattr(node, 'attributes') and 'id' in node.attributes:
            try:
                key_id = int(node.attributes['id'])
                logging.debug(f"_node_to_pre_key: found key_id={key_id} in attributes (fallback)")
            except (ValueError, TypeError) as e:
                logging.debug(f"_node_to_pre_key: error parsing key_id from attributes: {e}")
                return None

        if key_id is None:
            logging.debug("_node_to_pre_key: key_id is None")
        if public_key is None:
            logging.debug("_node_to_pre_key: public_key is None")
        elif len(public_key) not in (32, 33):
            logging.debug(f"_node_to_pre_key: invalid public_key length: {len(public_key)} (expected 32 or 33)")

        # X25519 public keys are 32 bytes, but sometimes they come with a 0x05 prefix (33 bytes)
        if key_id is None or public_key is None or len(public_key) not in (32, 33):
            return None
            
        # If the key has 33 bytes, validate the prefix but keep the full key
        if len(public_key) == 33:
            if public_key[0] != 0x05:
                logging.debug(f"_node_to_pre_key: invalid public_key prefix: {public_key[0]:02x} (expected 0x05)")
                return None
            
        result = PreKeyData(
            key_id=key_id,
            public_key=public_key,
            private_key=None,  # Private key is not available when parsing from a node
            uploaded=False  # Default to not uploaded since we don't know
        )
        logging.debug(f"_node_to_pre_key: returning {result}")
        return result

    def _pre_keys_to_nodes(self, pre_keys: List[PreKeyData]) -> List[Node]:
        """Implements preKeysToNodes from prekeys.go.

        Convert multiple pre-keys to nodes for server communication.

        Args:
            pre_keys: List of pre-keys to convert.

        Returns:
            List of converted nodes.
        """
        return [self._pre_key_to_node(key) for key in pre_keys]

    def _parse_pre_key_bundle(self, node: Node) -> PreKeyBundle:
        """Implements parsePreKeyBundle from prekeys.go.

        Parse a pre-key bundle from a server response.

        Args:
            node: The node containing the pre-key bundle.

        Returns:
            PreKeyBundle: The parsed pre-key bundle.

        Raises:
            PreKeyError: If the bundle is invalid or missing required fields.
        """
        try:
            if not isinstance(node, Node) or not hasattr(node, 'attributes') or not hasattr(node, 'content'):
                raise PreKeyError("Invalid node type")

            if 'registration' not in node.attributes:
                raise PreKeyError("missing registration")
            if 'device_id' not in node.attributes:
                raise PreKeyError("missing device ID")
                
            registration_id = int(node.attributes['registration'])
            device_id = int(node.attributes['device_id'])

            # Extract identity key
            identity_key = None
            signed_pre_key_node = None
            pre_key_node = None

            if not isinstance(node.content, list):
                raise PreKeyError("invalid node content")

            for child in node.content:
                if not isinstance(child, Node):
                    continue
                if child.tag == "identity" and isinstance(child.content, bytes):
                    identity_key = child.content
                elif child.tag == "skey":
                    signed_pre_key_node = child
                elif child.tag == "key":
                    pre_key_node = child

            if not identity_key:
                raise PreKeyError("missing identity key in bundle")
                
            # Validate identity key format (should be 33 bytes starting with 0x05)
            if len(identity_key) != 33 or identity_key[0] != 0x05:
                raise PreKeyError("invalid identity key format")
                
            if not signed_pre_key_node:
                raise PreKeyError("missing signed pre-key in bundle")

            # Extract signed pre-key data
            if 'id' not in signed_pre_key_node.attributes:
                raise PreKeyError("missing signed pre-key ID")
                
            signed_key_id = int(signed_pre_key_node.attributes['id'])
            signed_key_data = None
            signed_key_sig = None

            if isinstance(signed_pre_key_node.content, list):
                for child in signed_pre_key_node.content:
                    if not isinstance(child, Node):
                        continue
                    if child.tag == "key" and isinstance(child.content, bytes):
                        signed_key_data = child.content
                    elif child.tag == "signature" and isinstance(child.content, bytes):
                        signed_key_sig = child.content

            if not signed_key_data or not signed_key_sig:
                raise PreKeyError("invalid signed pre-key data in bundle")

            signed_pre_key = SignedPreKeyData(
                key_id=signed_key_id,
                public_key=signed_key_data,
                private_key=None,  # Not provided in bundle
                signature=signed_key_sig,
                timestamp=datetime.now()  # Server doesn't send timestamp
            )

            # Extract pre-key (optional)
            pre_key = None
            if pre_key_node and isinstance(pre_key_node.content, bytes):
                if 'id' not in pre_key_node.attributes:
                    raise PreKeyError("missing pre-key ID")
                pre_key_id = int(pre_key_node.attributes['id'])
                pre_key = PreKeyData(
                    key_id=pre_key_id,
                    public_key=pre_key_node.content,
                    private_key=None,  # Not provided in bundle
                    uploaded=True
                )

            return PreKeyBundle(
                registration_id=registration_id,
                device_id=device_id,
                pre_key=pre_key,
                signed_pre_key=signed_pre_key,
                identity_key=identity_key
            )

        except (KeyError, ValueError, AttributeError, TypeError) as e:
            raise PreKeyError(f"invalid pre-key bundle: {e}") from e

    async def fetch_pre_keys(self, users: List[JID]) -> Dict[JID, Tuple[Optional[PreKeyBundle], Optional[Exception]]]:
        """Implements whatsmeow.*Client.fetchPreKeys.

        Fetch pre-key bundles for multiple users.

        Args:
            users: List of user JIDs to fetch pre-keys for.

        Returns:
            Dictionary mapping user JIDs to tuples of (bundle, error).
            If successful, error will be None and bundle will be populated.
            If there was an error, bundle will be None and error will contain the exception.
        """
        results = {}

        for user in users:
            try:
                # This would be implemented by the Client class
                # node = await self._send_pre_key_fetch_request(user)
                # bundle = self._parse_pre_key_bundle(node)
                # results[user] = (bundle, None)
                results[user] = (None, NotImplementedError("fetch_pre_keys not implemented"))
            except Exception as e:
                results[user] = (None, e)

        return results

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
