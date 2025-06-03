"""
WhatsApp prekeys handling.

Port of whatsmeow/prekeys.go
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Union, Any, TYPE_CHECKING
import struct
import asyncio
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .exceptions import PreKeyError
from .binary.node import Node
from .types import JID
from .util.keys.keypair import PreKey

# Constants matching Go implementation
WANTED_PREKEY_COUNT = 50  # WantedPreKeyCount
MIN_PREKEY_COUNT = 5      # MinPreKeyCount
DJB_TYPE = 5             # ecc.DjbType - curve25519 key type

if TYPE_CHECKING:
    from .client import Client

@dataclass
class PreKeyBundle:
    """Pre-key bundle for Signal protocol - matches Go's prekey.Bundle."""
    registration_id: int
    device_id: int
    pre_key: Optional[PreKey]
    signed_pre_key: PreKey
    identity_key: bytes

@dataclass
class PreKeyResp:
    """Response structure for fetch_pre_keys - matches Go's preKeyResp struct."""
    bundle: Optional[PreKeyBundle]
    error: Optional[Exception]

def pre_key_to_node(key: PreKey) -> Node:
    """Port of Go's preKeyToNode function.

    Convert a pre-key to a binary Node with proper key ID encoding.

    Args:
        key: The pre-key to convert

    Returns:
        Node: The converted node
    """
    # Encode key ID as 4 bytes, then take last 3 bytes (matching Go's keyID[1:])
    key_id_bytes = struct.pack(">I", key.key_id)[1:]

    node = Node(
        tag="key",
        content=[
            Node(tag="id", content=key_id_bytes),
            Node(tag="value", content=key.pub),
        ]
    )

    # If this is a signed pre-key (has signature), use skey tag and add signature
    if key.signature is not None:
        node.tag = "skey"
        node.content.append(Node(tag="signature", content=key.signature))

    return node

def pre_keys_to_nodes(pre_keys: List[PreKey]) -> List[Node]:
    """Port of Go's preKeysToNodes function.

    Convert a list of pre-keys to a list of nodes.

    Args:
        pre_keys: List of pre-keys to convert

    Returns:
        List[Node]: List of converted nodes
    """
    return [pre_key_to_node(key) for key in pre_keys]

def node_to_pre_key(node: Node) -> Optional[PreKey]:
    """Port of Go's nodeToPreKey function.

    Parse a pre-key from a node.

    Args:
        node: The node to parse

    Returns:
        Optional[PreKey]: The parsed pre-key

    Raises:
        PreKeyError: If parsing fails
    """
    # Get ID tag
    id_node = node.get_child_by_tag("id")
    if not id_node or not isinstance(id_node.content, bytes):
        raise PreKeyError("prekey node doesn't contain ID tag")

    id_bytes = id_node.content
    if len(id_bytes) != 3:
        raise PreKeyError(f"prekey ID has unexpected number of bytes ({len(id_bytes)}, expected 3)")

    # Parse key ID from 3-byte big-endian (prepend zero byte)
    key_id = struct.unpack(">I", bytes([0]) + id_bytes)[0]

    # Get value tag
    value_node = node.get_child_by_tag("value")
    if not value_node or not isinstance(value_node.content, bytes):
        raise PreKeyError("prekey node doesn't contain value tag")

    public_key = value_node.content
    if len(public_key) != 32:
        raise PreKeyError(f"prekey value has unexpected number of bytes ({len(public_key)}, expected 32)")

    signature = None
    if node.tag == "skey":
        # This is a signed pre-key, get signature
        sig_node = node.get_child_by_tag("signature")
        if not sig_node or not isinstance(sig_node.content, bytes):
            raise PreKeyError("signed prekey node doesn't contain signature tag")

        signature = sig_node.content
        if len(signature) != 64:
            raise PreKeyError(f"prekey signature has unexpected number of bytes ({len(signature)}, expected 64)")

    # Create KeyPair with the public key only (private key is None since we're parsing from network)
    from .util.keys.keypair import KeyPair
    key_pair = KeyPair.from_public_key(public_key)

    return PreKey(
        key_pair=key_pair,
        key_id=key_id,
        signature=signature
    )

def node_to_pre_key_bundle(device_id: int, node: Node) -> PreKeyBundle:
    """Port of Go's nodeToPreKeyBundle function.

    Parse a pre-key bundle from a node.

    Args:
        device_id: The device ID
        node: The node to parse

    Returns:
        PreKeyBundle: The parsed pre-key bundle

    Raises:
        PreKeyError: If parsing fails
    """
    # Check for error node
    error_node, found = node.get_optional_child_by_tag("error")
    if error_node and error_node.tag == "error":
        raise PreKeyError(f"got error getting prekeys: {error_node.xml_string()}")

    # Get registration ID
    registration_node = node.get_child_by_tag("registration")
    if not registration_node or not isinstance(registration_node.content, bytes) or len(registration_node.content) != 4:
        raise PreKeyError("invalid registration ID in prekey response")

    registration_id = struct.unpack(">I", registration_node.content)[0]

    # Find keys node (might be directly in content or in a "keys" child node)
    keys_node, found = node.get_optional_child_by_tag("keys")
    if not keys_node:
        keys_node = node

    # Get identity key
    identity_key_node = keys_node.get_child_by_tag("identity")
    if not identity_key_node or not isinstance(identity_key_node.content, bytes) or len(identity_key_node.content) != 32:
        raise PreKeyError("invalid identity key in prekey response")

    identity_key = identity_key_node.content

    # Get pre-key (optional)
    pre_key = None
    pre_key_node, found = keys_node.get_optional_child_by_tag("key")
    if pre_key_node:
        pre_key = node_to_pre_key(pre_key_node)

    # Get signed pre-key (required)
    signed_pre_key_node = keys_node.get_child_by_tag("skey")
    if not signed_pre_key_node:
        raise PreKeyError("missing signed prekey in prekey response")

    signed_pre_key = node_to_pre_key(signed_pre_key_node)
    if not signed_pre_key or not signed_pre_key.signature:
        raise PreKeyError("invalid signed prekey in prekey response")

    return PreKeyBundle(
        registration_id=registration_id,
        device_id=device_id,
        pre_key=pre_key,
        signed_pre_key=signed_pre_key,
        identity_key=identity_key
    )

# Client method implementations using composition strategy
async def get_server_prekey_count(client: "Client", ctx: Any = None) -> int:
    """Port of Go's (*Client).getServerPreKeyCount method.

    Get the number of pre-keys stored on the WhatsApp server.

    Args:
        client: The client instance
        ctx: Context (unused in Python)

    Returns:
        int: Number of pre-keys on server

    Raises:
        PreKeyError: If the request fails
    """
    try:
        resp, err = await client.send_iq({
            "namespace": "encrypt",
            "type": "get",
            "to": client.server_jid,
            "content": [Node(tag="count")]
        })

        count_node = resp.get_child_by_tag("count")
        value = count_node.attrs.get("value")
        if value is None:
            raise PreKeyError("server response missing prekey count value")

        return int(value)

    except Exception as e:
        raise PreKeyError(f"failed to get prekey count on server: {e}") from e

async def upload_prekeys(client: "Client", ctx: Any = None) -> None:
    """Port of Go's (*Client).uploadPreKeys method.

    Upload pre-keys to the WhatsApp server with rate limiting.

    Args:
        client: The client instance
        ctx: Context (unused in Python)
    """
    async with client.upload_prekeys_lock:
        # Rate limiting - don't upload more than once every 10 minutes
        if (client.last_pre_key_upload and
            client.last_pre_key_upload + timedelta(minutes=10) > datetime.now()):
            try:
                server_count = await get_server_prekey_count(client, ctx)
                if server_count >= WANTED_PREKEY_COUNT:
                    client.send_log.debug("Canceling prekey upload request due to likely race condition")
                    return
            except Exception:
                pass  # Ignore errors getting server count

        # Get registration ID as 4-byte big-endian
        registration_id_bytes = struct.pack(">I", client.store.registration_id)

        # Get or generate pre-keys
        try:
            pre_keys = await client.store.pre_keys.get_or_gen_pre_keys(WANTED_PREKEY_COUNT)
        except Exception as e:
            client.send_log.error(f"Failed to get prekeys to upload: {e}")
            return

        client.send_log.info(f"Uploading {len(pre_keys)} new prekeys to server")

        # Build upload request
        content = [
            Node(tag="registration", content=registration_id_bytes),
            Node(tag="type", content=bytes([DJB_TYPE])),
            Node(tag="identity", content=client.store.identity_key.pub),
            Node(tag="list", content=pre_keys_to_nodes(pre_keys)),
            pre_key_to_node(client.store.signed_pre_key)
        ]

        try:
            await client.send_iq({
                "namespace": "encrypt",
                "type": "set",
                "to": client.server_jid,
                "content": content
            })
        except Exception as e:
            client.send_log.error(f"Failed to send request to upload prekeys: {e}")
            return

        client.send_log.debug("Got response to uploading prekeys")

        # Mark pre-keys as uploaded
        try:
            last_key_id = pre_keys[-1].key_id
            await client.store.pre_keys.mark_pre_keys_as_uploaded(last_key_id)
        except Exception as e:
            client.send_log.warning(f"Failed to mark prekeys as uploaded: {e}")
            return

        client.last_pre_key_upload = datetime.now()

async def fetch_pre_keys(client: "Client", ctx: Any, users: List[JID]) -> Dict[JID, PreKeyResp]:
    """Port of Go's (*Client).fetchPreKeys method.

    Fetch pre-key bundles for a list of users.

    Args:
        client: The client instance
        ctx: Context (unused in Python)
        users: List of user JIDs to fetch pre-keys for

    Returns:
        Dict[JID, PreKeyResp]: Map of JID to pre-key response

    Raises:
        PreKeyError: If the request fails
    """
    # Build user request nodes
    requests = []
    for user in users:
        requests.append(Node(
            tag="user",
            attributes={
                "jid": user,
                "reason": "identity"
            }
        ))

    # Send request
    try:
        resp, err = await client.send_iq({
            "namespace": "encrypt",
            "type": "get",
            "to": client.server_jid,
            "content": [Node(tag="key", content=requests)]
        })
    except Exception as e:
        raise PreKeyError(f"failed to send prekey request: {e}") from e

    children = resp.get_children()
    if not children:
        raise PreKeyError("got empty response to prekey request")

    # Parse response
    list_node = resp.get_child_by_tag("list")
    resp_data = {}

    for child in list_node.get_children():
        if child.tag != "user":
            continue

        jid = JID.from_string(child.attrs.get("jid", ""))
        try:
            bundle = node_to_pre_key_bundle(jid.device, child)
            resp_data[jid] = PreKeyResp(bundle=bundle, error=None)
        except Exception as e:
            resp_data[jid] = PreKeyResp(bundle=None, error=e)

    return resp_data

class PreKeyStore:
    """Manages WhatsApp pre-keys - matches Go's store interface."""

    def __init__(self):
        self._pre_keys: Dict[int, PreKey] = {}
        self._next_pre_key_id = 1
        self._uploaded_keys: set = set()

    async def get_or_gen_pre_keys(self, wanted_count: int = WANTED_PREKEY_COUNT) -> List[PreKey]:
        """Get existing unuploaded pre-keys or generate new ones if needed.

        Args:
            wanted_count: Number of pre-keys to return

        Returns:
            List of PreKey objects

        Raises:
            PreKeyError: If unable to generate sufficient keys
        """
        # Get existing unuploaded keys
        existing = [k for k in self._pre_keys.values() if k.key_id not in self._uploaded_keys]

        # If we don't have enough, generate more
        if len(existing) < wanted_count:
            needed = wanted_count - len(existing)
            new_keys = await self._generate_pre_keys(needed)
            existing.extend(new_keys)

        return existing[:wanted_count]

    async def _generate_pre_keys(self, count: int) -> List[PreKey]:
        """Generate new pre-keys.

        Args:
            count: Number of keys to generate

        Returns:
            List of generated PreKey objects
        """
        keys = []
        for _ in range(count):
            if self._next_pre_key_id > 0xFFFFFF:  # 24-bit limit
                break

            key_id = self._next_pre_key_id
            self._next_pre_key_id += 1

            # Generate PreKey using the class method
            key = PreKey.generate(key_id)
            self._pre_keys[key_id] = key
            keys.append(key)

        return keys

    async def mark_pre_keys_as_uploaded(self, up_to_key_id: int) -> None:
        """Mark pre-keys as uploaded up to the specified ID.

        Args:
            up_to_key_id: Highest key ID to mark as uploaded
        """
        for key_id in self._pre_keys:
            if key_id <= up_to_key_id:
                self._uploaded_keys.add(key_id)

    def get_pre_key(self, key_id: int) -> Optional[PreKey]:
        """Get a pre-key by ID.

        Args:
            key_id: The ID of the pre-key to retrieve

        Returns:
            The requested PreKey or None if not found
        """
        return self._pre_keys.get(key_id)

    async def remove_pre_key(self, key_id: int) -> None:
        """Remove a pre-key from the store.

        Args:
            key_id: The ID of the pre-key to remove
        """
        self._pre_keys.pop(key_id, None)
        self._uploaded_keys.discard(key_id)
