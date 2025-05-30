"""
WhatsApp Web pairing implementation.

Port of whatsmeow/pair.go
"""
import base64
import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable, Union, List, Dict, Any, Tuple
import asyncio

from .generated.waAdv import WAAdv_pb2
from .generated.waCommon import WACommon_pb2
from .generated.waDeviceCapabilities import WAProtobufsDeviceCapabilities_pb2
from .binary import wabinary
from .types import events, jid
from .util.keys.keypair import KeyPair
from .pair_code import PairClientType, pair_phone as pair_phone_impl, handle_code_pair_notification

# Constants for ADV prefixes
ADV_PREFIX_ACCOUNT_SIGNATURE = bytes([6, 0])
ADV_PREFIX_DEVICE_SIGNATURE_GENERATE = bytes([6, 1])
ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE = bytes([6, 5])
ADV_HOSTED_PREFIX_DEVICE_IDENTITY_DEVICE_SIGNATURE_VERIFICATION = bytes([6, 6])

from signal_protocol import curve

def concat_bytes(*data: bytes) -> bytes:
    """
    Concatenate multiple byte arrays.

    Args:
        *data: Variable number of byte arrays to concatenate

    Returns:
        The concatenated byte array
    """
    return b''.join(data)


# Error classes
class PairError(Exception):
    """Base class for pairing errors."""
    pass

class PairProtoError(PairError):
    """Error during protobuf operations in pairing."""
    def __init__(self, message: str, cause: Exception):
        self.cause = cause
        super().__init__(f"{message}: {cause}")

class PairDatabaseError(PairError):
    """Error during database operations in pairing."""
    def __init__(self, message: str, cause: Exception):
        self.cause = cause
        super().__init__(f"{message}: {cause}")

class PairInvalidDeviceIdentityHMACError(PairError):
    """Invalid HMAC in device identity."""
    pass

class PairInvalidDeviceSignatureError(PairError):
    """Invalid device signature."""
    pass

class PairRejectedLocallyError(PairError):
    """Pairing rejected by local callback."""
    pass


def safe_get_proto_field(proto_obj: Any, field_name: str, default: Any = None) -> Any:
    """
    Safely get a field from a protobuf object.

    Args:
        proto_obj: The protobuf object
        field_name: The name of the field to get
        default: The default value to return if the field is not present

    Returns:
        The field value or the default value
    """
    if not proto_obj or not hasattr(proto_obj, field_name):
        return default
    return getattr(proto_obj, field_name)


def safe_get_proto_bytes(proto_obj: Any, field_name: str) -> bytes:
    """
    Safely get a bytes field from a protobuf object.

    Args:
        proto_obj: The protobuf object
        field_name: The name of the field to get

    Returns:
        The field value as bytes or an empty bytes object

    Raises:
        TypeError: If the field is present but not bytes
    """
    value = safe_get_proto_field(proto_obj, field_name, b"")
    if value and not isinstance(value, bytes):
        raise TypeError(f"Expected bytes for field {field_name}, got {type(value)}")
    return value


def safe_get_proto_enum(proto_obj: Any, field_name: str, enum_type: Any, default: Any = None) -> Any:
    """
    Safely get an enum field from a protobuf object.

    Args:
        proto_obj: The protobuf object
        field_name: The name of the field to get
        enum_type: The enum type
        default: The default value to return if the field is not present

    Returns:
        The field value as an enum value or the default value
    """
    value = safe_get_proto_field(proto_obj, field_name)
    if value is None:
        return default
    try:
        return enum_type(value)
    except (ValueError, TypeError):
        return default


def safe_get_jid(attrs: Dict[str, Any], key: str) -> Optional[jid.JID]:
    """
    Safely get a JID from a dictionary of attributes.

    Args:
        attrs: The dictionary of attributes
        key: The key to get

    Returns:
        The JID or None if the key is not present or the value is not a valid JID
    """
    value = attrs.get(key)
    if value is None:
        return None

    if isinstance(value, jid.JID):
        return value

    try:
        if isinstance(value, str):
            return jid.JID.from_string(value)
        else:
            return None
    except Exception:
        return None


@dataclass
class PairConfig:
    """Configuration for device pairing."""
    timeout_seconds: int = 60
    show_pairing_error: bool = True
    show_pairing_ref: bool = True

class PairDevice:
    """Handles WhatsApp Web device pairing."""

    def __init__(self):
        self._qr_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self._ref_callback: Optional[Callable[[str], Awaitable[None]]] = None
        self.store = None
        self.log = None
        self.pre_pair_callback = None
        self.phone_linking_cache = None
        self._expect_disconnect = False

    def integrate_with_client(self, client: Any) -> None:
        """
        Integrate this PairDevice instance with a Client instance.

        This method sets up the necessary references between the PairDevice and Client
        instances to enable pairing functionality.

        Args:
            client: The Client instance to integrate with
        """
        # Set up references
        self.store = client.store
        self.log = client.log
        self.pre_pair_callback = client.pre_pair_callback

        # Set up methods
        client.send_node = self.send_node
        client.send_iq = self.send_iq
        client.dispatch_event = self.dispatch_event
        client.store_lid_pn_mapping = self.store_lid_pn_mapping
        client.handle_pair = self.handle_pair
        client.handle_pair_success = self.handle_pair_success
        client.verify_device_identity_account_signature = self.verify_device_identity_account_signature
        client.generate_device_signature = self.generate_device_signature
        client.send_pair_error = self.send_pair_error
        client.pair = self.pair
        client.pair_phone = self.pair_phone

        # Set up store integration methods
        client.get_device_identity = self.get_device_identity
        client.put_device_identity = self.put_device_identity
        client.delete_device_identity = self.delete_device_identity

        # Set up callbacks
        client.on_qr = self.on_qr
        client.on_pair_ref = self.on_pair_ref

    def on_qr(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set callback for when QR code is received."""
        self._qr_callback = callback

    def on_pair_ref(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """Set callback for when pairing reference is received."""
        self._ref_callback = callback

    def expect_disconnect(self) -> None:
        """Mark that a disconnect is expected."""
        self._expect_disconnect = True

    async def send_node(self, node: wabinary.Node) -> None:
        """
        Send a binary node to the server.

        Args:
            node: The node to send

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("send_node must be implemented by subclasses")

    async def send_iq(self, namespace: str, iq_type: str, to: jid.JID, content: wabinary.Node) -> wabinary.Node:
        """
        Send an IQ request to the server.

        Args:
            namespace: The namespace for the IQ
            iq_type: The type of IQ (get, set, result)
            to: The recipient JID
            content: The content node

        Returns:
            The response node

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("send_iq must be implemented by subclasses")

    def dispatch_event(self, event: Any) -> None:
        """
        Dispatch an event to listeners.

        Args:
            event: The event to dispatch

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("dispatch_event must be implemented by subclasses")

    async def store_lid_pn_mapping(self, ctx: Any, lid: jid.JID, pn: jid.JID) -> None:
        """
        Store a mapping between a long ID and a phone number JID.

        Args:
            ctx: The context for the operation
            lid: The long ID JID
            pn: The phone number JID

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        # This is an abstract method that should be implemented by concrete store implementations
        # The implementation should store the mapping between the long ID and phone number JID
        # in a persistent storage
        raise NotImplementedError("store_lid_pn_mapping must be implemented by subclasses")

    def disconnect(self) -> None:
        """
        Disconnect from the server.

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("disconnect must be implemented by subclasses")

    async def get_device_identity(self, ctx: Any, jid: jid.JID) -> Optional[bytes]:
        """
        Get the device identity for a JID.

        Args:
            ctx: The context for the operation
            jid: The JID to get the device identity for

        Returns:
            The device identity bytes or None if not found

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("get_device_identity must be implemented by subclasses")

    async def put_device_identity(self, ctx: Any, jid: jid.JID, identity: bytes) -> None:
        """
        Store the device identity for a JID.

        Args:
            ctx: The context for the operation
            jid: The JID to store the device identity for
            identity: The device identity bytes

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("put_device_identity must be implemented by subclasses")

    async def delete_device_identity(self, ctx: Any, jid: jid.JID) -> None:
        """
        Delete the device identity for a JID.

        Args:
            ctx: The context for the operation
            jid: The JID to delete the device identity for

        Raises:
            NotImplementedError: This method must be implemented by subclasses
        """
        raise NotImplementedError("delete_device_identity must be implemented by subclasses")

    async def handle_iq(self, node: wabinary.Node) -> None:
        """
        Handle an IQ node from the server.

        Args:
            node: The IQ node to handle
        """
        children = node.get_children()
        if len(children) != 1 or node.attrs.get("from") != jid.JID.new_server():
            return

        if children[0].tag == "pair-device":
            await self.handle_pair_device(node)
        elif children[0].tag == "pair-success":
            await self.handle_pair_success(node)

    async def handle_pair_device(self, node: wabinary.Node) -> None:
        """
        Handle a pair-device request from the server.

        Args:
            node: The pair-device node
        """
        pair_device = node.get_child_by_tag("pair-device")
        try:
            await self.send_node(wabinary.Node(
                tag="iq",
                attrs={
                    "to": node.attrs.get("from"),
                    "id": node.attrs.get("id"),
                    "type": "result",
                },
            ))
        except Exception as e:
            self.log.warning(f"Failed to send acknowledgement for pair-device request: {e}")

        evt = events.QR(codes=[])
        for i, child in enumerate(pair_device.get_children()):
            if child.tag != "ref":
                self.log.warning(f"pair-device node contains unexpected child tag {child.tag} at index {i}")
                continue

            content = child.content
            if not isinstance(content, bytes):
                self.log.warning(f"pair-device node contains unexpected child content type {type(content)} at index {i}")
                continue

            evt.codes.append(self.make_qr_data(content.decode()))

        self.dispatch_event(evt)

    def make_qr_data(self, ref: str) -> str:
        """
        Create QR data from a reference and device information.

        Args:
            ref: The reference string

        Returns:
            The QR data string
        """
        noise = base64.b64encode(self.store.noise_key.pub).decode()
        identity = base64.b64encode(self.store.identity_key.pub).decode()
        adv = base64.b64encode(self.store.adv_secret_key).decode()
        return f"{ref},{noise},{identity},{adv}"

    async def handle_pair_success(self, node: wabinary.Node) -> None:
        """
        Handle a pair-success response from the server.

        Args:
            node: The pair-success node
        """
        id_str = node.attrs.get("id")
        pair_success = node.get_child_by_tag("pair-success")

        device_identity_bytes = pair_success.get_child_by_tag("device-identity").content
        business_name = pair_success.get_child_by_tag("biz").attrs.get("name", "")
        device_jid = safe_get_jid(pair_success.get_child_by_tag("device").attrs, "jid")
        device_lid = safe_get_jid(pair_success.get_child_by_tag("device").attrs, "lid")
        platform = pair_success.get_child_by_tag("platform").attrs.get("name", "")

        if not device_jid or not device_lid:
            self.log.error("Invalid JID or LID in pair-success message")
            return

        # Handle pairing in a separate task
        asyncio.create_task(self._handle_pair_task(
            device_identity_bytes, id_str, business_name, platform, device_jid, device_lid
        ))

    async def _handle_pair_task(self, device_identity_bytes: bytes, req_id: str,
                               business_name: str, platform: str,
                               device_jid: jid.JID, device_lid: jid.JID) -> None:
        """
        Task to handle pairing after receiving pair-success.

        Args:
            device_identity_bytes: The device identity bytes
            req_id: The request ID
            business_name: The business name
            platform: The platform name
            device_jid: The device JID
            device_lid: The device long ID
        """
        # Create a context for the operation
        ctx = {}

        try:
            await self.handle_pair(ctx, device_identity_bytes, req_id,
                                  business_name, platform, device_jid, device_lid)
            self.log.info(f"Successfully paired {self.store.id}")
            self.dispatch_event(events.PairSuccess(
                id=device_jid,
                lid=device_lid,
                business_name=business_name,
                platform=platform
            ))
        except Exception as e:
            self.log.error(f"Failed to pair device: {e}")
            self.disconnect()
            self.dispatch_event(events.PairError(
                id=device_jid,
                lid=device_lid,
                business_name=business_name,
                platform=platform,
                error=e
            ))

    async def handle_pair(self, ctx: Any, device_identity_bytes: bytes, req_id: str,
                         business_name: str, platform: str,
                         device_jid: jid.JID, device_lid: jid.JID) -> None:
        """
        Handle the pairing process after receiving pair-success.

        Args:
            ctx: The context for the operation
            device_identity_bytes: The device identity bytes
            req_id: The request ID
            business_name: The business name
            platform: The platform name
            device_jid: The device JID
            device_lid: The device long ID

        Raises:
            PairProtoError: If there's an error parsing the protobuf messages
            PairInvalidDeviceIdentityHMACError: If the HMAC verification fails
            PairInvalidDeviceSignatureError: If the device signature verification fails
            PairRejectedLocallyError: If the pairing is rejected by the local callback
            PairDatabaseError: If there's an error storing data in the database
        """
        # Parse device identity container
        device_identity_container = WAAdv_pb2.ADVSignedDeviceIdentityHMAC()
        try:
            device_identity_container.ParseFromString(device_identity_bytes)
        except Exception as e:
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairProtoError("failed to parse device identity container in pair success message", e)

        is_hosted_account = (safe_get_proto_enum(
            device_identity_container,
            "account_type",
            WAAdv_pb2.ADVEncryptionType
        ) == WAAdv_pb2.ADVEncryptionType.HOSTED)

        # Verify HMAC
        h = hmac.new(self.store.adv_secret_key, digestmod=hashlib.sha256)
        if is_hosted_account:
            h.update(ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE)

        details = safe_get_proto_bytes(device_identity_container, "details")
        h.update(details)

        hmac_value = safe_get_proto_bytes(device_identity_container, "hmac")
        if h.digest() != hmac_value:
            self.log.warning("Invalid HMAC from pair success message")
            await self.send_pair_error(req_id, 401, "hmac-mismatch")
            raise PairInvalidDeviceIdentityHMACError()

        # Parse device identity
        device_identity = WAAdv_pb2.ADVSignedDeviceIdentity()
        try:
            device_identity.ParseFromString(details)
        except Exception as e:
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairProtoError("failed to parse signed device identity in pair success message", e)

        # Verify device identity signature
        if not self.verify_device_identity_account_signature(device_identity, self.store.identity_key, is_hosted_account):
            await self.send_pair_error(req_id, 401, "signature-mismatch")
            raise PairInvalidDeviceSignatureError()

        # Generate device signature
        device_identity.device_signature = self.generate_device_signature(
            device_identity, self.store.identity_key, is_hosted_account
        )

        # Parse device identity details
        device_identity_details = WAAdv_pb2.ADVDeviceIdentity()
        try:
            device_details = safe_get_proto_bytes(device_identity, "details")
            device_identity_details.ParseFromString(device_details)
        except Exception as e:
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairProtoError("failed to parse device identity details in pair success message", e)

        # Check pre-pair callback
        if self.pre_pair_callback is not None and not self.pre_pair_callback(device_jid, platform, business_name):
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairRejectedLocallyError()

        # Store account
        self.store.account = device_identity

        # Get main device identity
        main_device_lid = device_lid
        main_device_lid.device = 0
        main_device_identity = safe_get_proto_bytes(device_identity, "account_signature_key")
        device_identity.account_signature_key = b""

        # Marshal self-signed device identity
        try:
            self_signed_device_identity = device_identity.SerializeToString()
        except Exception as e:
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairProtoError("failed to marshal self-signed device identity", e)

        # Store device information
        self.store.id = device_jid
        self.store.lid = device_lid
        self.store.business_name = business_name
        self.store.platform = platform

        try:
            await self.store.save(ctx)
        except Exception as e:
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairDatabaseError("failed to save device store", e)

        await self.store_lid_pn_mapping(ctx, device_lid, device_jid)

        try:
            await self.store.identities.put_identity(ctx, main_device_lid.signal_address(), main_device_identity)
        except Exception as e:
            await self.store.delete(ctx)
            await self.send_pair_error(req_id, 500, "internal-error")
            raise PairDatabaseError("failed to store main device identity", e)

        # Expect disconnect after this
        self.expect_disconnect()

        # Send pairing confirmation
        try:
            await self.send_node(wabinary.Node(
                tag="iq",
                attrs={
                    "to": jid.JID.new_server(),
                    "type": "result",
                    "id": req_id,
                },
                content=[wabinary.Node(
                    tag="pair-device-sign",
                    content=[wabinary.Node(
                        tag="device-identity",
                        attrs={
                            "key-index": safe_get_proto_field(device_identity_details, "key_index", 0),
                        },
                        content=self_signed_device_identity,
                    )],
                )],
            ))
        except Exception as e:
            await self.store.delete(ctx)
            raise Exception(f"failed to send pairing confirmation: {e}")

        return None

    def verify_device_identity_account_signature(self, device_identity: WAAdv_pb2.ADVSignedDeviceIdentity,
                                               ikp: KeyPair, is_hosted_account: bool) -> bool:
        """
        Verify the account signature in a device identity.

        Args:
            device_identity: The device identity to verify
            ikp: The identity key pair
            is_hosted_account: Whether this is a hosted account

        Returns:
            True if the signature is valid, False otherwise
        """
        account_signature_key = safe_get_proto_bytes(device_identity, "account_signature_key")
        account_signature = safe_get_proto_bytes(device_identity, "account_signature")

        if len(account_signature_key) != 32 or len(account_signature) != 64:
            return False

        signature_key = curve.PublicKey(account_signature_key)
        signature = account_signature

        prefix = ADV_PREFIX_ACCOUNT_SIGNATURE
        if is_hosted_account:
            prefix = ADV_HOSTED_PREFIX_DEVICE_IDENTITY_ACCOUNT_SIGNATURE

        details = safe_get_proto_bytes(device_identity, "details")
        message = concat_bytes(prefix, details, ikp.pub)
        return signature_key.verify_signature(message, signature)

    def generate_device_signature(self, device_identity: WAAdv_pb2.ADVSignedDeviceIdentity,
                                ikp: KeyPair, is_hosted_account: bool) -> bytes:
        """
        Generate a device signature for a device identity.

        Args:
            device_identity: The device identity to sign
            ikp: The identity key pair
            is_hosted_account: Whether this is a hosted account

        Returns:
            The generated signature
        """
        prefix = ADV_PREFIX_DEVICE_SIGNATURE_GENERATE
        if is_hosted_account:
            prefix = ADV_HOSTED_PREFIX_DEVICE_IDENTITY_DEVICE_SIGNATURE_VERIFICATION

        details = safe_get_proto_bytes(device_identity, "details")
        account_signature_key = safe_get_proto_bytes(device_identity, "account_signature_key")

        message = concat_bytes(
            prefix,
            details,
            ikp.pub,
            account_signature_key
        )

        private_key = curve.PrivateKey(ikp.priv)
        return private_key.calculate_signature(message)

    async def send_pair_error(self, id_str: str, code: int, text: str) -> None:
        """
        Send a pairing error response.

        Args:
            id_str: The request ID
            code: The error code
            text: The error text
        """
        try:
            await self.send_node(wabinary.Node(
                tag="iq",
                attrs={
                    "to": jid.JID.new_server(),
                    "type": "error",
                    "id": id_str,
                },
                content=[wabinary.Node(
                    tag="error",
                    attrs={
                        "code": code,
                        "text": text,
                    },
                )],
            ))
        except Exception as e:
            self.log.error(f"Failed to send pair error node: {e}")

    async def pair(self, config: Optional[PairConfig] = None) -> None:
        """
        Start the pairing process.

        Args:
            config: The pairing configuration

        Raises:
            TimeoutError: If pairing times out
            NotImplementedError: This method must be implemented by subclasses
        """
        if config is None:
            config = PairConfig()

        # Create capabilities proto
        capabilities = WAProtobufsDeviceCapabilities_pb2.DeviceCapabilities()
        capabilities.platform = "pymeow"
        # TODO: Set proper capabilities

        try:
            # Start pairing process
            # This should be implemented by subclasses
            raise NotImplementedError("pair must be implemented by subclasses")
        except asyncio.TimeoutError:
            raise TimeoutError("Pairing timed out")

    async def pair_phone(
        self,
        number: str,
        show_push_notification: bool = True,
        client_type: Union[PairClientType, int] = PairClientType.CHROME,
        client_display_name: str = "Chrome (Windows)"
    ) -> str:
        """
        Generate a pairing code that can be used to link to a phone without scanning a QR code.

        You must connect the client normally before calling this (which means you'll also receive a QR code
        event, but that can be ignored when doing code pairing).

        Args:
            number: The phone number to pair with (international format without leading zeros)
            show_push_notification: Whether to show a push notification on the phone
            client_type: The type of client to use (one of the PairClientType constants)
            client_display_name: The display name for the client (must be formatted as "Browser (OS)")

        Returns:
            The pairing code to enter on the phone

        Raises:
            ValueError: If the phone number is invalid or the client is not connected
        """
        if isinstance(client_type, int):
            client_type = PairClientType(client_type)

        # Call the implementation from pair_code.py
        return await pair_phone_impl(
            self,
            None,  # context is not used in Python implementation
            number,
            show_push_notification,
            client_type,
            client_display_name
        )
