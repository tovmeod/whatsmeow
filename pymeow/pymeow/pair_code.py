"""
WhatsApp Web pairing with phone number and code.

Port of whatsmeow/pair-code.go
"""
import base64
import os
import re
from dataclasses import dataclass
from typing import Tuple

import nacl.bindings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .binary.node import Attrs, Node
from .types.jid import JID
from .util.hkdfutil.hkdf import sha256 as hkdf_sha256
from .util.keys.keypair import KeyPair


class PairCodeError(Exception):
    """Base exception for pair code operations."""
    pass


class PhoneNumberError(PairCodeError):
    """Invalid phone number format."""
    pass


class PairingRefMismatchError(PairCodeError):
    """Pairing reference mismatch."""
    pass


class CryptographicError(PairCodeError):
    """Cryptographic operation failed."""
    pass


# PairClientType is the type of client to use with PairCode
class PairClientType(int):
    """Type of client to use with PairCode."""
    UNKNOWN = 0
    CHROME = 1
    EDGE = 2
    FIREFOX = 3
    IE = 4
    OPERA = 5
    SAFARI = 6
    ELECTRON = 7
    UWP = 8
    OTHER_WEB_CLIENT = 9


# Regular expression to remove non-numeric characters from phone numbers
NOT_NUMBERS = re.compile(r"[^0-9]")

# Base32 encoding for linking codes
LINKING_BASE32 = base64.b32encode(b"123456789ABCDEFGHJKLMNPQRSTVWXYZ").decode()

# Phone validation constants
MIN_PHONE_LENGTH = 6

# Cryptographic constants
PBKDF2_ITERATIONS = 2 << 16
EPHEMERAL_KEY_SIZE = 80
SALT_SIZE = 32
IV_SIZE = 16
LINKING_CODE_SIZE = 5
KEY_BUNDLE_NONCE_SIZE = 12
ADV_SECRET_SIZE = 32


@dataclass
class PhoneLinkingCache:
    """Cache for phone linking information."""
    jid: JID
    key_pair: KeyPair
    linking_code: str
    pairing_ref: str


def _validate_phone_number(phone: str) -> str:
    """Validate and clean phone number format."""
    cleaned = NOT_NUMBERS.sub("", phone)
    if len(cleaned) <= MIN_PHONE_LENGTH:
        raise PhoneNumberError("Phone number too short")
    if cleaned.startswith("0"):
        raise PhoneNumberError("International phone number required (must not start with 0)")
    return cleaned


def generate_companion_ephemeral_key() -> Tuple[KeyPair, bytes, str]:
    """
    Generate ephemeral key for companion device.

    Returns:
        Tuple containing:
        - ephemeral_key_pair: The generated key pair
        - ephemeral_key: The encoded ephemeral key
        - encoded_linking_code: The linking code for pairing
    """
    ephemeral_key_pair = KeyPair.generate()
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    linking_code = os.urandom(LINKING_CODE_SIZE)
    encoded_linking_code = base64.b32encode(linking_code).decode()

    # Generate link code key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=SALT_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    link_code_key = kdf.derive(encoded_linking_code.encode())

    # Encrypt the public key
    cipher = Cipher(algorithms.AES(link_code_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encrypted_pubkey = encryptor.update(ephemeral_key_pair.pub) + encryptor.finalize()

    # Combine salt, IV, and encrypted pubkey
    ephemeral_key = bytearray(EPHEMERAL_KEY_SIZE)
    ephemeral_key[0:SALT_SIZE] = salt
    ephemeral_key[SALT_SIZE:SALT_SIZE+IV_SIZE] = iv
    ephemeral_key[SALT_SIZE+IV_SIZE:EPHEMERAL_KEY_SIZE] = encrypted_pubkey

    return ephemeral_key_pair, bytes(ephemeral_key), encoded_linking_code


async def pair_phone(client, ctx, phone: str, show_push_notification: bool, client_type: PairClientType, client_display_name: str) -> str:
    """
    Generate a pairing code that can be used to link to a phone without scanning a QR code.

    Args:
        client: The WhatsApp client
        ctx: The context for the request
        phone: The phone number to pair with
        show_push_notification: Whether to show a push notification on the phone
        client_type: The type of client to use
        client_display_name: The display name for the client

    Returns:
        The formatted pairing code

    Raises:
        ValueError: If the phone number is invalid
    """
    if client is None:
        raise ValueError("Client is nil")

    ephemeral_key_pair, ephemeral_key, encoded_linking_code = generate_companion_ephemeral_key()

    # Clean up and validate phone number
    phone = _validate_phone_number(phone)

    jid = JID.new_user_jid(phone)

    # Create IQ request
    resp = await client.send_iq(
        namespace="md",
        iq_type="set",
        to=JID.new_server(),
        content=Node(
            tag="link_code_companion_reg",
            attrs=Attrs({
                "jid": jid,
                "stage": "companion_hello",
                "should_show_push_notification": str(show_push_notification).lower(),
            }),
            content=[
                Node(tag="link_code_pairing_wrapped_companion_ephemeral_pub", content=ephemeral_key),
                Node(tag="companion_server_auth_key_pub", content=client.store.noise_key.pub),
                Node(tag="companion_platform_id", content=str(int(client_type))),
                Node(tag="companion_platform_display", content=client_display_name),
                Node(tag="link_code_pairing_nonce", content=bytes([0])),
            ]
        )
    )

    # Extract pairing reference
    pairing_ref_node, ok = resp.get_optional_child_by_tag("link_code_companion_reg", "link_code_pairing_ref")
    if not ok:
        raise ValueError("Missing link_code_pairing_ref in code link registration response")

    pairing_ref = pairing_ref_node.content
    if not isinstance(pairing_ref, bytes):
        raise ValueError(f"Unexpected type {type(pairing_ref)} in content of link_code_pairing_ref tag")

    # Store in cache
    client.phone_linking_cache = PhoneLinkingCache(
        jid=jid,
        key_pair=ephemeral_key_pair,
        linking_code=encoded_linking_code,
        pairing_ref=pairing_ref.decode(),
    )

    # Format the code with a hyphen
    return f"{encoded_linking_code[0:4]}-{encoded_linking_code[4:]}"


async def handle_code_pair_notification(client, ctx, parent_node: Node) -> None:
    """
    Handle a code pair notification from the server.

    Args:
        client: The WhatsApp client
        ctx: The context for the request
        parent_node: The notification node

    Raises:
        ValueError: If there's an error processing the notification
    """
    try:
        await _handle_code_pair_notification(client, ctx, parent_node)
    except Exception as e:
        client.log.error(f"Failed to handle code pair notification: {e}")


async def _handle_code_pair_notification(client, ctx, parent_node: Node) -> None:
    """
    Internal implementation of handle_code_pair_notification.

    Args:
        client: The WhatsApp client
        ctx: The context for the request
        parent_node: The notification node

    Raises:
        ValueError: If there's an error processing the notification
    """
    node, ok = parent_node.get_optional_child_by_tag("link_code_companion_reg")
    if not ok:
        raise ValueError("Missing link_code_companion_reg in notification")

    link_cache = client.phone_linking_cache
    if link_cache is None:
        raise ValueError("Received code pair notification without a pending pairing")

    link_code_pairing_ref = node.get_child_by_tag("link_code_pairing_ref").content
    if isinstance(link_code_pairing_ref, bytes) and link_code_pairing_ref.decode() != link_cache.pairing_ref:
        raise PairingRefMismatchError("Pairing ref mismatch in code pair notification")

    wrapped_primary_ephemeral_pub = node.get_child_by_tag("link_code_pairing_wrapped_primary_ephemeral_pub").content
    if not isinstance(wrapped_primary_ephemeral_pub, bytes):
        raise ValueError("Missing link_code_pairing_wrapped_primary_ephemeral_pub in notification")

    primary_identity_pub = node.get_child_by_tag("primary_identity_pub").content
    if not isinstance(primary_identity_pub, bytes):
        raise ValueError("Missing primary_identity_pub in notification")

    # Generate random values
    adv_secret_random = os.urandom(ADV_SECRET_SIZE)
    key_bundle_salt = os.urandom(SALT_SIZE)
    key_bundle_nonce = os.urandom(KEY_BUNDLE_NONCE_SIZE)

    # Decrypt the primary device's ephemeral public key
    primary_salt = wrapped_primary_ephemeral_pub[0:SALT_SIZE]
    primary_iv = wrapped_primary_ephemeral_pub[SALT_SIZE:SALT_SIZE+IV_SIZE]
    primary_encrypted_pubkey = wrapped_primary_ephemeral_pub[SALT_SIZE+IV_SIZE:EPHEMERAL_KEY_SIZE]

    # Generate link code key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=SALT_SIZE,
        salt=primary_salt,
        iterations=PBKDF2_ITERATIONS,
    )
    link_code_key = kdf.derive(link_cache.linking_code.encode())

    # Decrypt the primary device's public key
    cipher = Cipher(algorithms.AES(link_code_key), modes.CTR(primary_iv))
    decryptor = cipher.decryptor()
    primary_decrypted_pubkey = decryptor.update(primary_encrypted_pubkey) + decryptor.finalize()

    # Compute shared secret
    try:
        ephemeral_shared_secret = nacl.bindings.crypto_scalarmult(
            link_cache.key_pair.priv,
            primary_decrypted_pubkey
        )
    except Exception as e:
        raise CryptographicError(f"Failed to compute ephemeral shared secret: {e}")

    # Encrypt and wrap key bundle
    try:
        key_bundle_encryption_key = hkdf_sha256(
            ephemeral_shared_secret,
            key_bundle_salt,
            b"link_code_pairing_key_bundle_encryption_key",
            SALT_SIZE
        )
    except Exception as e:
        raise CryptographicError(f"Failed to derive key bundle encryption key: {e}")

    # Create GCM cipher for key bundle
    cipher = Cipher(
        algorithms.AES(key_bundle_encryption_key),
        modes.GCM(key_bundle_nonce)
    )
    encryptor = cipher.encryptor()

    # Combine identity keys and random data
    plaintext_key_bundle = client.store.identity_key.pub + primary_identity_pub + adv_secret_random

    # Encrypt the key bundle
    encrypted_key_bundle = encryptor.update(plaintext_key_bundle) + encryptor.finalize()

    # Combine salt, nonce, and encrypted bundle
    wrapped_key_bundle = key_bundle_salt + key_bundle_nonce + encrypted_key_bundle

    # Compute the adv secret key
    try:
        identity_shared_key = nacl.bindings.crypto_scalarmult(
            client.store.identity_key.priv,
            primary_identity_pub
        )
    except Exception as e:
        raise CryptographicError(f"Failed to compute identity shared key: {e}")

    adv_secret_input = ephemeral_shared_secret + identity_shared_key + adv_secret_random
    try:
        adv_secret = hkdf_sha256(adv_secret_input, None, b"adv_secret", ADV_SECRET_SIZE)
    except Exception as e:
        raise CryptographicError(f"Failed to derive ADV secret key: {e}")
    client.store.adv_secret_key = adv_secret

    # Send the final pairing message
    await client.send_iq(
        namespace="md",
        iq_type="set",
        to=JID.new_server(),
        content=Node(
            tag="link_code_companion_reg",
            attrs=Attrs({
                "jid": link_cache.jid,
                "stage": "companion_finish",
            }),
            content=[
                Node(tag="link_code_pairing_wrapped_key_bundle", content=wrapped_key_bundle),
                Node(tag="companion_identity_public", content=client.store.identity_key.pub),
                Node(tag="link_code_pairing_ref", content=link_code_pairing_ref),
            ]
        )
    )


def concat_bytes(*data: bytes) -> bytes:
    """
    Concatenate multiple byte arrays.

    Args:
        *data: Variable number of byte arrays to concatenate

    Returns:
        The concatenated byte array
    """
    return b''.join(data)
