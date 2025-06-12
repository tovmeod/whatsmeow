"""
WhatsApp prekeys handling.

Port of whatsmeow/prekeys.go
"""
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, TYPE_CHECKING, Tuple
import struct
from datetime import datetime, timedelta

from signal_protocol.state import PreKeyBundle
from . import request
from .binary.node import Node
from .request import InfoQuery, InfoQueryType
from .types import JID
from .util.keys.keypair import PreKey, KeyPair

# Constants matching Go implementation
WANTED_PREKEY_COUNT = 50  # WantedPreKeyCount
MIN_PREKEY_COUNT = 5      # MinPreKeyCount
DJB_TYPE = 5             # ecc.DjbType - curve25519 key type

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)


# @dataclass
# class PreKeyBundle:
#     """Pre-key bundle for Signal protocol - matches Go's prekey.Bundle."""
#     registration_id: int
#     device_id: int
#     pre_key: Optional[PreKey]
#     signed_pre_key: PreKey
#     identity_key: bytes

@dataclass
class PreKeyResp:
    """Response structure for fetch_pre_keys - matches Go's preKeyResp struct."""
    bundle: Optional[PreKeyBundle]
    error: Optional[Exception]

async def get_server_pre_key_count(client: "Client") -> int:
    """Port of Go's (*Client).getServerPreKeyCount method.

    Get the number of pre-keys stored on the WhatsApp server.

    Args:
        client: The client instance

    Returns:
        int: Number of pre-keys on server
    Raises:
        RuntimeError
        ValueError
    """
    # TODO: Review client.send_iq to ensure its signature and behavior
    #       (especially error reporting) align with Go's sendIQ.
    # TODO: Review client.server_jid to ensure it's the correct equivalent of types.ServerJID.
    # TODO: Review Node class and its methods like get_child_by_tag and attribute access.

    resp_node, err_send_iq = await request.send_iq(
        client,
        InfoQuery(namespace="encrypt", type=InfoQueryType.GET,
                  to=client.server_jid, content=[Node(tag="count")])
    )

    if err_send_iq is not None:
        raise RuntimeError(f"failed to get prekey count on server: {err_send_iq}")

    if resp_node is None:  # Should ideally be covered by err_send_iq, but good for robustness
        raise RuntimeError("failed to get prekey count on server: no response node received")

    count_node = resp_node.get_child_by_tag("count")
    if count_node is None:
        raise ValueError("server response missing 'count' node")

    value_str = count_node.attrs.get("value")
    if value_str is None:
        raise ValueError("server response 'count' node missing 'value' attribute")

    val = int(value_str)
    return val


async def upload_prekeys(client: "Client") -> None:
    """
    Port of Go's (*Client).uploadPreKeys method.

    Upload pre-keys to the WhatsApp server with rate limiting.

    Args:
        client: The client instance.
    """
    # Go: cli.uploadPreKeysLock.Lock() / defer cli.uploadPreKeysLock.Unlock()
    async with client.upload_prekeys_lock:
        # Go: if cli.lastPreKeyUpload.Add(10 * time.Minute).After(time.Now()) { ... }
        # Rate limiting - don't upload more than once every 10 minutes
        if client.last_pre_key_upload and client.last_pre_key_upload + timedelta(minutes=10) > datetime.now():
            # Go: sc, _ := cli.getServerPreKeyCount(ctx)
            # Call the Python equivalent, which should return (count, error)
            # ctx is not used in Python, so we don't pass it here.
            try:
                server_count = await get_server_pre_key_count(client)
            except Exception as e:
                # Go ignores the error from getServerPreKeyCount in this specific check
                # Go: if sc >= WantedPreKeyCount { ... }
                if server_count >= WANTED_PREKEY_COUNT:
                    # Go: cli.Log.Debugf(...)
                    client.send_log.debug("Canceling prekey upload request due to likely race condition")
                    # Go: return
                    logger.exception(e)
                    return

            # If err_get_count is not None, Go ignores it and proceeds, so we do nothing here.

        # Go: var registrationIDBytes [4]byte; binary.BigEndian.PutUint32(registrationIDBytes[:], cli.Store.RegistrationID)
        # Get registration ID as 4-byte big-endian
        registration_id_bytes = struct.pack(">I", client.store.registration_id)

        # Go: preKeys, err := cli.Store.PreKeys.GetOrGenPreKeys(ctx, WantedPreKeyCount)
        # Get or generate pre-keys
        try:
            # Assuming GetOrGenPreKeys in Python is async and takes count, not ctx
            pre_keys = await client.store.pre_keys.get_or_gen_pre_keys(WANTED_PREKEY_COUNT)
        # Go: if err != nil { cli.Log.Errorf(...); return }
        except Exception as e: # Catching broad Exception to match Go's general error check
            client.send_log.error(f"Failed to get prekeys to upload: {e}")
            return

        # Go: cli.Log.Infof("Uploading %d new prekeys to server", len(preKeys))
        client.send_log.info(f"Uploading {len(pre_keys)} new prekeys to server")

        # Go: _, err = cli.sendIQ(...)
        # Build upload request
        content = [
            Node(tag="registration", content=registration_id_bytes), # Go: {Tag: "registration", Content: registrationIDBytes[:]}
            Node(tag="type", content=bytes([DJB_TYPE])), # Go: {Tag: "type", Content: []byte{ecc.DjbType}}
            Node(tag="identity", content=client.store.identity_key.pub), # Go: {Tag: "identity", Content: cli.Store.IdentityKey.Pub[:]}
            Node(tag="list", content=pre_keys_to_nodes(pre_keys)), # Go: {Tag: "list", Content: preKeysToNodes(preKeys)}
            pre_key_to_node(client.store.signed_pre_key) # Go: preKeyToNode(cli.Store.SignedPreKey)
        ]

        try:
            # Go: _, err = cli.sendIQ(...)
            # Assuming send_iq in Python raises exceptions on failure, matching the try/except pattern here
            await client.send_iq(InfoQuery(namespace="encrypt", type=InfoQueryType.SET, to=client.server_jid, content=content))
        # Go: if err != nil { cli.Log.Errorf(...); return }
        except Exception as e: # Catching broad Exception to match Go's general error check
            client.send_log.error(f"Failed to send request to upload prekeys: {e}")
            return

        # Go: cli.Log.Debugf("Got response to uploading prekeys")
        client.send_log.debug("Got response to uploading prekeys")

        # Go: err = cli.Store.PreKeys.MarkPreKeysAsUploaded(ctx, preKeys[len(preKeys)-1].KeyID)
        # Mark pre-keys as uploaded
        try:
            # Go: preKeys[len(preKeys)-1].KeyID
            last_key_id = pre_keys[-1].key_id
            # Assuming MarkPreKeysAsUploaded in Python is async and takes key_id, not ctx
            await client.store.pre_keys.mark_pre_keys_as_uploaded(last_key_id)
        # Go: if err != nil { cli.Log.Warnf(...); return }
        except Exception as e: # Catching broad Exception to match Go's general error check
            client.send_log.warning(f"Failed to mark prekeys as uploaded: {e}")
            # Go returns here, so we return here as well.
            return

        # Go: cli.lastPreKeyUpload = time.Now()
        client.last_pre_key_upload = datetime.now()

        # Go: return (implicit nil error)
        # Python returns None implicitly

async def fetch_pre_keys(
    client: "Client",
    users: List[JID]
) -> Optional[Dict[JID, PreKeyResp]]:
    """
    Port of Go's (*Client).fetchPreKeys method.

    Fetch pre-key bundles for a list of users.
    This Python port returns a dictionary and an error object, similar to Go.

    Args:
        client: The client instance.
        users: List of user JIDs to fetch pre-keys for.

    Returns:
        Optional[Dict[JID, PreKeyResp]]:
            Map of JID to pre-key response.
    Raises:
        RuntimeError
        ValueError
    """
    # TODO: Review client.send_iq to ensure its signature and behavior
    #       (especially error reporting) align with Go's sendIQ.
    #       The Go version passes `ctx` to `sendIQ`.
    # TODO: Review client.server_jid to ensure it's the correct equivalent of types.ServerJID.
    # TODO: Review Node class for attribute naming (e.g., attributes vs. Attrs).
    # TODO: Review JID type for how it's represented as a string in Node attributes.

    # Go: requests := make([]waBinary.Node, len(users))
    request_nodes: List[Node] = []
    for user_jid in users:
        # Go: requests[i].Tag = "user"
        # Go: requests[i].Attrs = waBinary.Attrs{"jid": user, "reason": "identity"}
        request_nodes.append(Node(
            tag="user",
            # Assuming Node attributes are passed as a dict.
            # The original Python used 'attributes', Go uses 'Attrs'.
            # Ensure Node constructor matches.
            attrs={
                "jid": str(user_jid), # Ensure JID is stringified as expected by the server
                "reason": "identity"
            }
        ))

    # Go: resp, err := cli.sendIQ(...)
    # Assuming client.send_iq is adapted to return (response, error_object)
    resp_node = await request.send_iq(
        client,
        InfoQuery(namespace="encrypt", type=InfoQueryType.GET, to=client.server_jid,
                  content=[Node(tag="key", content=request_nodes)]))

    if resp_node is None: # Should not happen if err_send_iq is None, but for robustness
        raise RuntimeError("failed to send prekey request: no response node received")

    # Go: else if len(resp.GetChildren()) == 0 { return nil, fmt.Errorf("got empty response to prekey request") }
    # Assuming get_children() returns a list of child nodes.
    # The original Python port checked `if not children:`.
    # Go checks `len(resp.GetChildren()) == 0`. If `resp` itself is the top-level IQ response,
    # its children might be the actual content like <list>.
    # If `resp_node` is the direct parent of <list>, then `resp_node.get_children()` might be relevant.
    # For now, assuming `get_child_by_tag("list")` is the primary way to get the relevant data.
    # If the server can send an empty <iq type="result"></iq> without a <list> child,
    # then a check on `list_node` being None later is more direct.

    # Go: list := resp.GetChildByTag("list")
    list_node = resp_node.get_child_by_tag("list")
    if list_node is None:
        # This covers the case where the <list> tag is missing, which could imply an empty or malformed response.
        raise ValueError("got malformed response to prekey request: missing 'list' node")


    # Go: respData := make(map[types.JID]preKeyResp)
    resp_data: Dict["JID", "PreKeyResp"] = {}

    # Go: for _, child := range list.GetChildren() { ... }
    # Assuming list_node.get_children() returns the <user> nodes
    user_children = list_node.get_children()
    if not user_children and not request_nodes: # If we requested no users, an empty list is fine.
        return resp_data
    if not user_children and request_nodes: # If we requested users but got an empty list.
         raise ValueError("got empty 'list' node in prekey response when users were requested")


    for child_node in user_children:
        # Go: if child.Tag != "user" { continue }
        if child_node.tag != "user":
            continue

        # Go: jid := child.AttrGetter().JID("jid")
        # Python: jid = JID.from_string(child.attrs.get("jid", ""))
        # Assuming child_node.attributes is the dict of attributes
        jid_str = child_node.attrs.get("jid")
        if not jid_str:
            # Log or handle missing JID attribute? Go's AttrGetter().JID might panic or return zero JID.
            # For robustness, skip if JID is missing.
            # client.send_log.warning("User node in prekey response missing JID attribute") # If logging exists
            continue

        try:
            # TODO: Confirm JID.from_string exists and works as expected.
            jid = JID.from_string(jid_str)
        except Exception as e_jid_parse:
            logger.warning(f"Failed to parse JID '{jid_str}' from prekey response: {e_jid_parse}")
            continue

        # Go: bundle, err := nodeToPreKeyBundle(uint32(jid.Device), child)
        # Go: respData[jid] = preKeyResp{bundle, err}
        try:
            # TODO: Confirm jid.device attribute exists and is of the correct type for uint32 conversion.
            # The original Python port directly passed jid.device.
            device_id = int(jid.device) # Ensure it's an int if node_to_pre_key_bundle expects it.
            bundle = await node_to_pre_key_bundle(device_id, child_node) # Assuming async
            resp_data[jid] = PreKeyResp(bundle=bundle, error=None)
        except Exception as e: # Catching broad Exception to mirror Go's err in preKeyResp
            resp_data[jid] = PreKeyResp(bundle=None, error=e)

    # Go: return respData, nil
    return resp_data

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

async def node_to_pre_key_bundle(
    device_id: int,  # Go: deviceID uint32
    node: "Node"
) -> Optional["PreKeyBundle"]:
    """
    Port of Go's nodeToPreKeyBundle function.

    Parses a pre-key bundle from a node.

    Args:
        device_id: The device ID.
        node: The node to parse.

    Returns:
        Optional[PreKeyBundle]: The parsed pre-key bundle
    Raises:
        ValueError
    """
    # Go: errorNode, ok := node.GetOptionalChildByTag("error")
    # Go: if ok && errorNode.Tag == "error" { ... }
    # Python: error_node, found = node.get_optional_child_by_tag("error")
    # Python: if error_node and error_node.tag == "error":
    # Assuming get_optional_child_by_tag returns (Node|None, bool) in Python,
    # or just Node|None and the boolean check is on error_node itself.
    # The provided Python uses `error_node, found = ...`, let's stick to that pattern.
    error_node, found_error_node = node.get_optional_child_by_tag("error")
    if found_error_node and error_node is not None and error_node.tag == "error":
        xml_string_val = error_node.xml_string() if hasattr(error_node, 'xml_string') else str(error_node)
        raise ValueError(f"got error getting prekeys: {xml_string_val}") # Using ValueError for parsing issues

    # Go: registrationBytes, ok := node.GetChildByTag("registration").Content.([]byte)
    # Go: if !ok || len(registrationBytes) != 4 { ... }
    registration_node = node.get_child_by_tag("registration")
    if registration_node is None or not isinstance(registration_node.content, bytes) or len(registration_node.content) != 4:
        raise ValueError("invalid registration ID in prekey response")
    registration_id_bytes = registration_node.content
    # Go: registrationID := binary.BigEndian.Uint32(registrationBytes)
    registration_id = struct.unpack(">I", registration_id_bytes)[0]

    # Go: keysNode, ok := node.GetOptionalChildByTag("keys")
    # Go: if !ok { keysNode = node }
    # Python: keys_node, found = node.get_optional_child_by_tag("keys")
    # Python: if not keys_node: keys_node = node
    keys_node_optional, found_keys_node = node.get_optional_child_by_tag("keys")
    if found_keys_node and keys_node_optional is not None:
        keys_node = keys_node_optional
    else:
        keys_node = node # Fallback if "keys" child is not present

    # Go: identityKeyRaw, ok := keysNode.GetChildByTag("identity").Content.([]byte)
    # Go: if !ok || len(identityKeyRaw) != 32 { ... }
    identity_key_node = keys_node.get_child_by_tag("identity")
    if identity_key_node is None or not isinstance(identity_key_node.content, bytes) or len(identity_key_node.content) != 32:
        raise ValueError("invalid identity key in prekey response")
    identity_key_pub_bytes = identity_key_node.content
    # Go: identityKeyPub := *(*[32]byte)(identityKeyRaw) -> Python uses bytes directly

    # Go: preKeyNode, ok := keysNode.GetOptionalChildByTag("key")
    # Go: preKey := &keys.PreKey{}
    # Go: if ok { preKey, err = nodeToPreKey(preKeyNode); if err != nil { ... } }
    # Python: pre_key_node, found = keys_node.get_optional_child_by_tag("key")
    # Python: if pre_key_node: pre_key = node_to_pre_key(pre_key_node)
    parsed_pre_key_obj: Optional["PreKey"] = None
    pre_key_node_optional, found_pre_key_node = keys_node.get_optional_child_by_tag("key")
    # The `ok` in Go for preKeyNode determines if preKey.KeyID and preKey.Pub are used later.
    # In Python, this translates to whether `parsed_pre_key_obj` is None or not.

    if found_pre_key_node and pre_key_node_optional is not None:
        # Assuming node_to_pre_key is async and returns (PreKey|None, Error|None)
        temp_pre_key, err_pre_key = await node_to_pre_key(pre_key_node_optional)
        if err_pre_key is not None:
            raise ValueError(f"invalid prekey in prekey response: {err_pre_key}")
        if temp_pre_key is None: # Should not happen if err_pre_key is None, but good check
             raise ValueError("failed to parse prekey but no error reported by node_to_pre_key")
        parsed_pre_key_obj = temp_pre_key

    # Go: signedPreKey, err := nodeToPreKey(keysNode.GetChildByTag("skey"))
    # Go: if err != nil { ... }
    # Python: signed_pre_key_node = keys_node.get_child_by_tag("skey")
    # Python: if not signed_pre_key_node: raise PreKeyError(...)
    # Python: signed_pre_key = node_to_pre_key(signed_pre_key_node)
    # Python: if not signed_pre_key or not signed_pre_key.signature: raise PreKeyError(...)
    skey_node = keys_node.get_child_by_tag("skey")
    if skey_node is None:
        raise ValueError("missing signed prekey ('skey' node) in prekey response")

    parsed_signed_pre_key_obj, err_signed_pre_key = await node_to_pre_key(skey_node)
    if err_signed_pre_key is not None:
        raise ValueError(f"invalid signed prekey in prekey response: {err_signed_pre_key}")
    if parsed_signed_pre_key_obj is None: # Should not happen if err_signed_pre_key is None
        raise ValueError("failed to parse signed prekey but no error reported by node_to_pre_key")
    if parsed_signed_pre_key_obj.signature is None: # Go's `*signedPreKey.Signature` implies it must exist
        raise ValueError("parsed signed prekey is missing signature")


    # Constructing the bundle. The Python PreKeyBundle constructor seems simpler,
    # directly taking PreKey objects and identity_key bytes.
    # The Go version constructs intermediate ecc/identity objects.
    # This difference depends on the PreKeyBundle Python class design.
    # For a direct port of Go's NewBundle logic, the Python PreKeyBundle
    # would need to accept the individual components as Go does.
    # The provided Python code passes `pre_key` (our `parsed_pre_key_obj`),
    # `signed_pre_key` (our `parsed_signed_pre_key_obj`), and `identity_key` (our `identity_key_pub_bytes`).
    # This implies the Python PreKeyBundle constructor is different.
    #
    # To match Go's NewBundle structure more closely, we'd do:
    # if parsed_pre_key_obj is not None:
    #     bundle = PreKeyBundle.new_bundle_detailed( # Hypothetical detailed constructor
    #         registration_id=registration_id,
    #         device_id=device_id,
    #         pre_key_id_optional=NewOptionalUint32(parsed_pre_key_obj.key_id),
    #         signed_pre_key_id=parsed_signed_pre_key_obj.key_id,
    #         pre_key_public_optional=NewDjbECPublicKey(parsed_pre_key_obj.pub),
    #         signed_pre_key_public=NewDjbECPublicKey(parsed_signed_pre_key_obj.pub),
    #         signed_pre_key_signature=parsed_signed_pre_key_obj.signature,
    #         identity_key_obj=NewIdentityKey(NewDjbECPublicKey(identity_key_pub_bytes))
    #     )
    # else:
    #     bundle = PreKeyBundle.new_bundle_detailed(
    #         registration_id=registration_id,
    #         device_id=device_id,
    #         pre_key_id_optional=NewEmptyUint32(),
    #         signed_pre_key_id=parsed_signed_pre_key_obj.key_id,
    #         pre_key_public_optional=None, # Or specific sentinel for nil DjbECPublicKey
    #         signed_pre_key_public=NewDjbECPublicKey(parsed_signed_pre_key_obj.pub),
    #         signed_pre_key_signature=parsed_signed_pre_key_obj.signature,
    #         identity_key_obj=NewIdentityKey(NewDjbECPublicKey(identity_key_pub_bytes))
    #     )
    #
    # However, following the provided Python's simpler PreKeyBundle constructor:
    try:
        bundle = PreKeyBundle(
            registration_id=registration_id,
            device_id=device_id,
            pre_key=parsed_pre_key_obj, # This will be None if optional prekey wasn't found/parsed
            signed_pre_key=parsed_signed_pre_key_obj,
            identity_key=identity_key_pub_bytes # Assuming PreKeyBundle handles creating IdentityKey internally
        )
    except Exception as e: # Catch errors during PreKeyBundle instantiation
        raise RuntimeError(f"failed to create prekey bundle") from e

    return bundle

async def node_to_pre_key(node: "Node") -> Tuple[Optional[PreKey], Optional[Exception]]:
    """Port of Go's nodeToPreKey function (adapted for error tuple return).

    Parse a pre-key from a node.

    Args:
        node: The node to parse.

    Returns:
        Tuple[Optional[PreKey], Optional[Exception]]: The parsed pre-key and an
            Exception if an error occurred, otherwise None.
    """
    try:
        # Go: if id := node.GetChildByTag("id"); id.Tag != "id" { ... }
        # Go: else if idBytes, ok := id.Content.([]byte); !ok { ... }
        # Go: else if len(idBytes) != 3 { ... }
        # Get ID tag
        id_node = node.get_child_by_tag("id")
        if id_node is None: # Equivalent to Go's id.Tag != "id" check after GetChildByTag
            return None, ValueError("prekey node doesn't contain ID tag")

        if not isinstance(id_node.content, bytes): # Equivalent to Go's ok check on content type
             return None, ValueError(f"prekey ID has unexpected content ({type(id_node.content).__name__})")

        id_bytes = id_node.content
        if len(id_bytes) != 3: # Equivalent to Go's length check
            return None, ValueError(f"prekey ID has unexpected number of bytes ({len(id_bytes)}, expected 3)")

        # Go: key.KeyID = binary.BigEndian.Uint32(append([]byte{0}, idBytes...))
        # Parse key ID from 3-byte big-endian (prepend zero byte)
        key_id = struct.unpack(">I", bytes([0]) + id_bytes)[0]

        # Go: if pubkey := node.GetChildByTag("value"); pubkey.Tag != "value" { ... }
        # Go: else if pubkeyBytes, ok := pubkey.Content.([]byte); !ok { ... }
        # Go: else if len(pubkeyBytes) != 32 { ... }
        # Get value tag
        value_node = node.get_child_by_tag("value")
        if value_node is None: # Equivalent to Go's pubkey.Tag != "value" check
            return None, ValueError("prekey node doesn't contain value tag")

        if not isinstance(value_node.content, bytes): # Equivalent to Go's ok check on content type
            return None, ValueError(f"prekey value has unexpected content ({type(value_node.content).__name__})")

        public_key = value_node.content
        if len(public_key) != 32: # Equivalent to Go's length check
            return None, ValueError(f"prekey value has unexpected number of bytes ({len(public_key)}, expected 32)")

        signature_bytes: Optional[bytes] = None
        # Go: if node.Tag == "skey" { ... }
        if node.tag == "skey":
            # Go: if sig := node.GetChildByTag("signature"); sig.Tag != "signature" { ... }
            # Go: else if sigBytes, ok := sig.Content.([]byte); !ok { ... }
            # Go: else if len(sigBytes) != 64 { ... }
            # This is a signed pre-key, get signature
            sig_node = node.get_child_by_tag("signature")
            if sig_node is None: # Equivalent to Go's sig.Tag != "signature" check
                return None, ValueError("signed prekey node doesn't contain signature tag")

            if not isinstance(sig_node.content, bytes): # Equivalent to Go's ok check on content type
                return None, ValueError(f"prekey signature has unexpected content ({type(sig_node.content).__name__})")

            signature_bytes = sig_node.content
            if len(signature_bytes) != 64: # Equivalent to Go's length check
                return None, ValueError(f"prekey signature has unexpected number of bytes ({len(signature_bytes)}, expected 64)")

        # Go: key := keys.PreKey{KeyPair: keys.KeyPair{}, KeyID: 0, Signature: nil}
        # Go: key.KeyPair.Pub = (*[32]byte)(pubkeyBytes)
        # Go: key.Signature = (*[64]byte)(sigBytes)
        # Create KeyPair with the public key only
        key_pair = KeyPair.from_public_key(public_key)

        pre_key_obj = PreKey(
            key_pair=key_pair,
            key_id=key_id,
            signature=signature_bytes
        )
        # Go: return &key, nil
        return pre_key_obj, None

    except Exception as e: # Catch any unexpected error during parsing
        # This broad except is to ensure we always return the (None, Exception) tuple
        # if something unexpected goes wrong, similar to how Go's error propagation would work.
        # Specific ValueErrors are returned above for known issues.
        return None, RuntimeError(f"unexpected error parsing prekey node: {e}")

def pre_keys_to_nodes(pre_keys: List[PreKey]) -> List[Node]:
    """Port of Go's preKeysToNodes function.

    Convert a list of pre-keys to a list of nodes.

    Args:
        pre_keys: List of pre-keys to convert

    Returns:
        List[Node]: List of converted nodes
    """
    return [pre_key_to_node(key) for key in pre_keys]
