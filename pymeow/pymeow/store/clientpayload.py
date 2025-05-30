"""Client payload generation for WhatsApp Web.

Port of whatsmeow/store/clientpayload.go
"""

import hashlib
import struct
from typing import List, Optional, Tuple

from ..generated.waWa6 import WAWebProtobufsWa6_pb2
from ..generated.waCompanionReg import WACompanionReg_pb2
from ..types.jid import JID, EMPTY_JID
from ..util.keys.keypair import KeyPair

# WhatsApp web client version
WA_VERSION = [2, 3000, 1022781640]
WA_VERSION_HASH = hashlib.md5(".".join(map(str, WA_VERSION)).encode()).digest()

# Base client payload with default values
BASE_CLIENT_PAYLOAD = WAWebProtobufsWa6_pb2.ClientPayload(
    user_agent=WAWebProtobufsWa6_pb2.ClientPayload.UserAgent(
        platform=WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.Platform.WEB,
        release_channel=WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        app_version=WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.AppVersion(
            primary=WA_VERSION[0],
            secondary=WA_VERSION[1],
            tertiary=WA_VERSION[2]
        ),
        mcc="000",
        mnc="000",
        os_version="0.1.0",
        manufacturer="",
        device="Desktop",
        os_build_number="0.1.0",
        locale_language_iso6391="en",
        locale_country_iso31661alpha2="en"
    ),
    web_info=WAWebProtobufsWa6_pb2.ClientPayload.WebInfo(
        web_sub_platform=WAWebProtobufsWa6_pb2.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER
    ),
    connect_type=WAWebProtobufsWa6_pb2.ClientPayload.ConnectType.WIFI_UNKNOWN,
    connect_reason=WAWebProtobufsWa6_pb2.ClientPayload.ConnectReason.USER_ACTIVATED
)

# Device properties for registration
DEVICE_PROPS = WACompanionReg_pb2.DeviceProps(
    os="whatsmeow",
    version=WACompanionReg_pb2.DeviceProps.AppVersion(
        primary=0,
        secondary=1,
        tertiary=0
    ),
    platform_type=WACompanionReg_pb2.DeviceProps.PlatformType.UNKNOWN,
    require_full_sync=False
)

def set_os_info(name: str, version: Tuple[int, int, int]) -> None:
    """Set OS information in the device properties and base client payload.

    Args:
        name: OS name
        version: OS version as a tuple of (major, minor, patch)
    """
    global DEVICE_PROPS, BASE_CLIENT_PAYLOAD

    DEVICE_PROPS.os = name
    DEVICE_PROPS.version.primary = version[0]
    DEVICE_PROPS.version.secondary = version[1]
    DEVICE_PROPS.version.tertiary = version[2]

    version_str = f"{version[0]}.{version[1]}.{version[2]}"
    BASE_CLIENT_PAYLOAD.user_agent.os_version = version_str
    BASE_CLIENT_PAYLOAD.user_agent.os_build_number = version_str

def get_registration_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for device registration.

    Args:
        device: Device object

    Returns:
        ClientPayload for registration
    """
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    reg_id_bytes = struct.pack(">I", device.registration_id)
    prekey_id_bytes = struct.pack(">I", device.signed_pre_key.key_id)

    device_props_bytes = DEVICE_PROPS.SerializeToString()

    payload.device_pairing_data.e_regid = reg_id_bytes
    payload.device_pairing_data.e_keytype = b"\x05"  # DjbType
    payload.device_pairing_data.e_ident = device.identity_key.public
    payload.device_pairing_data.e_skey_id = prekey_id_bytes[1:]
    payload.device_pairing_data.e_skey_val = device.signed_pre_key.pub
    payload.device_pairing_data.e_skey_sig = device.signed_pre_key.signature
    payload.device_pairing_data.build_hash = WA_VERSION_HASH
    payload.device_pairing_data.device_props = device_props_bytes

    payload.passive = False
    payload.pull = False

    return payload

def get_login_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for login.

    Args:
        device: Device object

    Returns:
        ClientPayload for login
    """
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    payload.username = device.id.user_int()
    payload.device = device.id.device
    payload.passive = True
    payload.pull = True

    return payload

def get_client_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get appropriate client payload based on device state.

    Args:
        device: Device object

    Returns:
        ClientPayload for either login or registration
    """
    if device.id is not None:
        if device.id == EMPTY_JID:
            raise ValueError("get_client_payload called with empty JID")
        return get_login_payload(device)
    else:
        return get_registration_payload(device)
