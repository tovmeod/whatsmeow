"""
WhatsApp Web pairing implementation.
Port of whatsmeow/pair.go
"""

import base64
import hashlib
import hmac
import logging
from typing import TYPE_CHECKING

from signal_protocol import curve

from .binary.node import Node
from .generated.waAdv import WAAdv_pb2
from .types import events, jid
from .util.keys.keypair import KeyPair

logger = logging.getLogger(__name__)

# Constants from Go
ADV_PREFIX_ACCOUNT_SIGNATURE = bytes([6, 0])
ADV_PREFIX_DEVICE_SIGNATURE_GENERATE = bytes([6, 1])
ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE = bytes([6, 5])
ADV_HOSTED_PREFIX_DEVICE_IDENTITY_DEVICE_SIGNATURE_VERIFICATION = bytes([6, 6])

if TYPE_CHECKING:
    from .client import Client


# Error classes
class PairError(Exception):
    pass

class PairProtoError(PairError):
    def __init__(self, message: str, cause: Exception):
        self.cause = cause
        super().__init__(f"{message}: {cause}")

class PairDatabaseError(PairError):
    def __init__(self, message: str, cause: Exception):
        self.cause = cause
        super().__init__(f"{message}: {cause}")

class PairInvalidDeviceIdentityHMACError(PairError):
    pass

class PairInvalidDeviceSignatureError(PairError):
    pass

class PairRejectedLocallyError(PairError):
    pass

# Error constants (equivalent to Go variables)
ErrPairInvalidDeviceIdentityHMAC = PairInvalidDeviceIdentityHMACError()
ErrPairInvalidDeviceSignature = PairInvalidDeviceSignatureError()
ErrPairRejectedLocally = PairRejectedLocallyError()

def concat_bytes(*data: bytes) -> bytes:
    """Concatenate multiple byte arrays."""
    return b''.join(data)

async def handle_iq(client: "Client", node: Node) -> None:
    """Handle an IQ node for pairing."""
    children = node.get_children()
    if len(children) != 1 or node.attrs.get("from") != jid.SERVER_JID:
        return

    if children[0].tag == "pair-device":
        await handle_pair_device(client, node)
    elif children[0].tag == "pair-success":
        await handle_pair_success(client, node)

async def handle_pair_device(client: "Client", node: Node) -> None:
    """Handle a pair-device request from the server."""
    pair_device = node.get_child_by_tag("pair-device")
    try:
        await client.send_node(Node(
            tag="iq",
            attrs={
                "to": node.attrs.get("from"),
                "id": node.attrs.get("id"),
                "type": "result",
            },
        ))
    except Exception as e:
        logger.warning(f"Failed to send acknowledgement for pair-device request: {e}")

    evt = events.QR(codes=[])
    for i, child in enumerate(pair_device.get_children()):
        if child.tag != "ref":
            logger.warning(f"pair-device node contains unexpected child tag {child.tag} at index {i}")
            continue

        content = child.content
        if not isinstance(content, bytes):
            logger.warning(f"pair-device node contains unexpected child content type {type(content)} at index {i}")
            continue

        evt.codes.append(make_qr_data(client, content.decode()))

    await client.dispatch_event(evt)

def make_qr_data(client: "Client", ref: str) -> str:
    """Create QR data from a reference and device information."""
    noise = base64.b64encode(client.store.noise_key.pub).decode()
    identity = base64.b64encode(client.store.identity_key.pub).decode()
    adv = base64.b64encode(client.store.adv_secret_key).decode()
    return f"{ref},{noise},{identity},{adv}"

async def handle_pair_success(client: "Client", node: Node) -> None:
    """Handle a pair-success response from the server."""
    req_id = str(node.attrs.get("id"))
    pair_success = node.get_child_by_tag("pair-success")

    device_identity_bytes = pair_success.get_child_by_tag("device-identity").content
    business_name = pair_success.get_child_by_tag("biz").attrs.get("name", "")

    device_jid_node = pair_success.get_child_by_tag("device")
    device_jid_str = device_jid_node.attrs.get("jid")
    device_lid_str = device_jid_node.attrs.get("lid")

    device_jid = jid.JID.parse_jid(device_jid_str) if device_jid_str else jid.EMPTY_JID
    device_lid = jid.JID.parse_jid(device_lid_str) if device_lid_str else jid.EMPTY_JID

    platform = pair_success.get_child_by_tag("platform").attrs.get("name", "")

    # Handle pairing in a separate task (equivalent to Go's goroutine)
    await _handle_pair_task(client, device_identity_bytes, req_id,
                                         business_name, platform, device_jid, device_lid)

async def _handle_pair_task(client: "Client", device_identity_bytes: bytes, req_id: str,
                           business_name: str, platform: str, device_jid: jid.JID, device_lid: jid.JID) -> None:
    """Task to handle pairing after receiving pair-success."""
    try:
        await handle_pair(client, device_identity_bytes, req_id, business_name, platform, device_jid, device_lid)
        logger.info(f"Successfully paired {client.store.id}")
        await client.dispatch_event(events.PairSuccess(
            id=device_jid, lid=device_lid, business_name=business_name, platform=platform
        ))
    except Exception as e:
        logger.error(f"Failed to pair device: {e}")
        await client.disconnect()
        await client.dispatch_event(events.PairError(
            id=device_jid, lid=device_lid, business_name=business_name, platform=platform, error=e
        ))

async def handle_pair(client: "Client", device_identity_bytes: bytes, req_id: str,
                     business_name: str, platform: str, device_jid: jid.JID, device_lid: jid.JID) -> None:
    """Handle the main pairing process."""
    # Parse device identity container
    device_identity_container = WAAdv_pb2.ADVSignedDeviceIdentityHMAC()
    try:
        device_identity_container.ParseFromString(device_identity_bytes)
    except Exception as e:
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairProtoError("failed to parse device identity container in pair success message", e)

    # Check if it's a hosted account
    is_hosted_account = (device_identity_container.HasField('accountType') and
                        device_identity_container.accountType == WAAdv_pb2.ADVEncryptionType.HOSTED)

    # Verify HMAC
    h = hmac.new(client.store.adv_secret_key, digestmod=hashlib.sha256)
    if is_hosted_account:
        h.update(ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE)
    h.update(device_identity_container.details)

    if h.digest() != device_identity_container.HMAC:
        logger.warning("Invalid HMAC from pair success message")
        await send_pair_error(client, req_id, 401, "hmac-mismatch")
        raise ErrPairInvalidDeviceIdentityHMAC

    # Parse device identity
    device_identity = WAAdv_pb2.ADVSignedDeviceIdentity()
    try:
        device_identity.ParseFromString(device_identity_container.details)
    except Exception as e:
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairProtoError("failed to parse signed device identity in pair success message", e)

    # Verify device identity signature
    if not verify_device_identity_account_signature(device_identity, client.store.identity_key, is_hosted_account):
        await send_pair_error(client, req_id, 401, "signature-mismatch")
        raise ErrPairInvalidDeviceSignature

    # Generate device signature
    device_identity.deviceSignature = generate_device_signature(device_identity, client.store.identity_key, is_hosted_account)

    # Parse device identity details
    device_identity_details = WAAdv_pb2.ADVDeviceIdentity()
    try:
        device_identity_details.ParseFromString(device_identity.details)
    except Exception as e:
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairProtoError("failed to parse device identity details in pair success message", e)

    # Check pre-pair callback
    if client.pre_pair_callback is not None and not client.pre_pair_callback(device_jid, platform, business_name):
        await send_pair_error(client, req_id, 500, "internal-error")
        raise ErrPairRejectedLocally

    # Store account (equivalent to proto.Clone in Go)
    client.store.account = WAAdv_pb2.ADVSignedDeviceIdentity()
    client.store.account.CopyFrom(device_identity)

    # Get main device identity - create new JID with device=0
    main_device_lid = jid.JID(
        user=device_lid.user,
        server=device_lid.server,
        raw_agent=device_lid.raw_agent,
        device=0,
        integrator=device_lid.integrator
    )
    main_device_identity = device_identity.accountSignatureKey
    device_identity.accountSignatureKey = b""

    # Marshal self-signed device identity
    try:
        self_signed_device_identity = device_identity.SerializeToString()
    except Exception as e:
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairProtoError("failed to marshal self-signed device identity", e)

    # Store device information
    client.store.id = device_jid
    client.store.lid = device_lid
    client.store.business_name = business_name
    client.store.platform = platform

    try:
        await client.store.save()
    except Exception as e:
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairDatabaseError("failed to save device store", e)

    await client.store_lid_pn_mapping(device_lid, device_jid)

    try:
        await client.store.identities.put_identity(str(main_device_lid.signal_address()), main_device_identity)
    except Exception as e:
        await client.store.delete()
        await send_pair_error(client, req_id, 500, "internal-error")
        raise PairDatabaseError("failed to store main device identity", e)

    # Expect disconnect after this
    client._expect_disconnect()

    # Send pairing confirmation
    try:
        await client.send_node(Node(
            tag="iq",
            attrs={
                "to": jid.SERVER_JID,
                "type": "result",
                "id": req_id,
            },
            content=[Node(
                tag="pair-device-sign",
                content=[Node(
                    tag="device-identity",
                    attrs={
                        "key-index": device_identity_details.keyIndex,
                    },
                    content=self_signed_device_identity,
                )],
            )],
        ))
    except Exception as e:
        await client.store.delete()
        raise Exception("failed to send pairing confirmation") from e

def verify_device_identity_account_signature(device_identity: WAAdv_pb2.ADVSignedDeviceIdentity,
                                           ikp: KeyPair, is_hosted_account: bool) -> bool:
    """Verify the account signature in a device identity."""
    if len(device_identity.accountSignatureKey) != 32 or len(device_identity.accountSignature) != 64:
        return False

    try:
        signature_key = curve.PublicKey.deserialize(device_identity.accountSignatureKey)
        signature = device_identity.accountSignature

        prefix = ADV_PREFIX_ACCOUNT_SIGNATURE
        if is_hosted_account:
            prefix = ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE

        message = concat_bytes(prefix, device_identity.details, ikp.pub)
        return signature_key.verify_signature(message, signature)
    except Exception:
        return False

def generate_device_signature(device_identity: WAAdv_pb2.ADVSignedDeviceIdentity,
                            ikp: KeyPair, is_hosted_account: bool) -> bytes:
    """Generate a device signature for a device identity."""
    prefix = ADV_PREFIX_DEVICE_SIGNATURE_GENERATE
    if is_hosted_account:
        prefix = ADV_HOSTED_PREFIX_DEVICE_IDENTITY_DEVICE_SIGNATURE_VERIFICATION

    message = concat_bytes(
        prefix,
        device_identity.details,
        ikp.pub,
        device_identity.accountSignatureKey
    )

    private_key = curve.PrivateKey.deserialize(ikp.priv)
    return private_key.calculate_signature(message)

async def send_pair_error(client: "Client", req_id: str, code: int, text: str) -> None:
    """Send a pairing error response."""
    try:
        await client.send_node(Node(
            tag="iq",
            attrs={
                "to": jid.SERVER_JID,
                "type": "error",
                "id": req_id,
            },
            content=[Node(
                tag="error",
                attrs={
                    "code": code,
                    "text": text,
                },
            )],
        ))
    except Exception as e:
        logger.error(f"Failed to send pair error node: {e}")
