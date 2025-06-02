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

# WhatsApp web client version - matches Go's waVersion
WA_VERSION = [2, 3000, 1022781640]

def get_wa_version_hash() -> bytes:
    """Get the MD5 hash of the version string - matches Go's waVersionHash."""
    version_str = ".".join(map(str, WA_VERSION))
    return hashlib.md5(version_str.encode()).digest()

def create_proto_string(value: str) -> str:
    """Helper to create protobuf string - matches Go's proto.String()."""
    return value

def create_proto_uint32(value: int) -> int:
    """Helper to create protobuf uint32 - matches Go's proto.Uint32()."""
    return value

def create_proto_bool(value: bool) -> bool:
    """Helper to create protobuf bool - matches Go's proto.Bool()."""
    return value

def create_proto_enum(enum_value):
    """Helper to create protobuf enum - matches Go's .Enum()."""
    return enum_value

# Create base client payload - matches Go's BaseClientPayload
def create_base_client_payload() -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Create base client payload exactly matching Go implementation."""
    payload = WAWebProtobufsWa6_pb2.ClientPayload()

    # Set user agent - matches Go's BaseClientPayload.UserAgent
    payload.userAgent.platform = WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.Platform.WEB
    payload.userAgent.releaseChannel = WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.ReleaseChannel.RELEASE
    payload.userAgent.appVersion.primary = WA_VERSION[0]
    payload.userAgent.appVersion.secondary = WA_VERSION[1]
    payload.userAgent.appVersion.tertiary = WA_VERSION[2]
    payload.userAgent.mcc = "000"
    payload.userAgent.mnc = "000"
    payload.userAgent.osVersion = "0.1.0"
    payload.userAgent.manufacturer = ""
    payload.userAgent.device = "Desktop"
    payload.userAgent.osBuildNumber = "0.1.0"
    payload.userAgent.localeLanguageIso6391 = "en"
    payload.userAgent.localeCountryIso31661Alpha2 = "en"

    # Set web info - matches Go's BaseClientPayload.WebInfo
    payload.webInfo.webSubPlatform = WAWebProtobufsWa6_pb2.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER

    # Set connection info - matches Go's BaseClientPayload
    payload.connectType = WAWebProtobufsWa6_pb2.ClientPayload.ConnectType.WIFI_UNKNOWN
    payload.connectReason = WAWebProtobufsWa6_pb2.ClientPayload.ConnectReason.USER_ACTIVATED

    return payload

# Global base client payload - matches Go's BaseClientPayload
BASE_CLIENT_PAYLOAD = create_base_client_payload()

# Device properties - matches Go's DeviceProps
def create_device_props() -> WACompanionReg_pb2.DeviceProps:
    """Create device properties exactly matching Go implementation."""
    device_props = WACompanionReg_pb2.DeviceProps()
    device_props.os = "whatsmeow"
    device_props.version.primary = 0
    device_props.version.secondary = 1
    device_props.version.tertiary = 0
    device_props.platformType = WACompanionReg_pb2.DeviceProps.PlatformType.UNKNOWN
    device_props.requireFullSync = False
    return device_props

DEVICE_PROPS = create_device_props()

def set_os_info(name: str, version: Tuple[int, int, int]) -> None:
    """Set OS information - matches Go's SetOSInfo function."""
    global DEVICE_PROPS, BASE_CLIENT_PAYLOAD

    DEVICE_PROPS.os = name
    DEVICE_PROPS.version.primary = version[0]
    DEVICE_PROPS.version.secondary = version[1]
    DEVICE_PROPS.version.tertiary = version[2]

    version_str = f"{version[0]}.{version[1]}.{version[2]}"
    BASE_CLIENT_PAYLOAD.userAgent.osVersion = version_str
    BASE_CLIENT_PAYLOAD.userAgent.osBuildNumber = version_str

def get_registration_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for device registration - matches Go's getRegistrationPayload."""
    # Clone the base payload - matches Go's proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    # Create registration ID bytes - matches Go's regID := make([]byte, 4); binary.BigEndian.PutUint32(regID, device.RegistrationID)
    reg_id = bytearray(4)
    struct.pack_into(">I", reg_id, 0, device.registration_id)

    # Create pre-key ID bytes - matches Go's preKeyID := make([]byte, 4); binary.BigEndian.PutUint32(preKeyID, device.SignedPreKey.KeyID)
    pre_key_id = bytearray(4)
    struct.pack_into(">I", pre_key_id, 0, device.signed_pre_key.key_id)

    # Marshal device props - matches Go's deviceProps, _ := proto.Marshal(DeviceProps)
    device_props_bytes = DEVICE_PROPS.SerializeToString()

    # Create device pairing data - matches Go's payload.DevicePairingData = &waWa6.ClientPayload_DevicePairingRegistrationData{...}
    device_pairing_data = WAWebProtobufsWa6_pb2.ClientPayload.DevicePairingRegistrationData()
    device_pairing_data.eRegid = bytes(reg_id)
    device_pairing_data.eKeytype = bytes([5])  # matches Go's []byte{ecc.DjbType}
    device_pairing_data.eIdent = device.identity_key.pub  # matches Go's device.IdentityKey.Pub[:]
    device_pairing_data.eSkeyID = bytes(pre_key_id[1:])  # matches Go's preKeyID[1:]
    device_pairing_data.eSkeyVal = device.signed_pre_key.public_key  # matches Go's device.SignedPreKey.Pub[:]
    device_pairing_data.eSkeySig = device.signed_pre_key.signature  # matches Go's device.SignedPreKey.Signature[:]
    device_pairing_data.buildHash = get_wa_version_hash()  # matches Go's waVersionHash[:]
    device_pairing_data.deviceProps = device_props_bytes

    # Set device pairing data on payload
    payload.devicePairingData.CopyFrom(device_pairing_data)

    # Set flags - matches Go's payload.Passive = proto.Bool(false); payload.Pull = proto.Bool(false)
    payload.passive = False
    payload.pull = False

    return payload

def get_login_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for login - matches Go's getLoginPayload."""
    # Clone the base payload - matches Go's proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    # Set username and device - matches Go's payload.Username = proto.Uint64(device.ID.UserInt()); payload.Device = proto.Uint32(uint32(device.ID.Device))
    payload.username = device.id.user_int()
    payload.device = device.id.device

    # Set flags - matches Go's payload.Passive = proto.Bool(true); payload.Pull = proto.Bool(true)
    payload.passive = True
    payload.pull = True

    return payload

def get_client_payload(device) -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get appropriate client payload based on device state - matches Go's GetClientPayload."""
    if device.id is not None:
        if device.id == EMPTY_JID:
            raise ValueError("GetClientPayload called with empty JID")
        return get_login_payload(device)
    else:
        return get_registration_payload(device)
