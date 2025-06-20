"""Client payload generation for WhatsApp Web.

Port of whatsmeow/store/clientpayload.go
"""

import hashlib
import struct
from typing import Tuple

from .store import Device
from ..generated.waCompanionReg import WACompanionReg_pb2
from ..generated.waWa6 import WAWebProtobufsWa6_pb2
from ..datatypes.jid import EMPTY_JID


class WAVersionContainer:
    """Container for WhatsApp web version number - matches Go's WAVersionContainer."""

    def __init__(self, major: int = 0, minor: int = 0, patch: int = 0):
        """Initialize version container with three version numbers."""
        self._version = [major, minor, patch]

    @classmethod
    def parse_version(cls, version: str) -> 'WAVersionContainer':
        """Parse version string into WAVersionContainer - matches Go's ParseVersion."""
        parts = version.split('.')
        if len(parts) != 3:
            raise ValueError(f"'{version}' doesn't contain three dot-separated parts")

        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
        except ValueError as e:
            raise ValueError(f"Invalid version format '{version}': {e}")

        return cls(major, minor, patch)

    def less_than(self, other: 'WAVersionContainer') -> bool:
        """Compare versions - matches Go's LessThan."""
        return (self._version[0] < other._version[0] or
                (self._version[0] == other._version[0] and self._version[1] < other._version[1]) or
                (self._version[0] == other._version[0] and self._version[1] == other._version[1] and self._version[2] < other._version[2]))

    def is_zero(self) -> bool:
        """Check if version is zero - matches Go's IsZero."""
        return self._version == [0, 0, 0]

    def __str__(self) -> str:
        """String representation - matches Go's String."""
        return '.'.join(str(part) for part in self._version)

    def hash(self) -> bytes:
        """MD5 hash of string representation - matches Go's Hash."""
        return hashlib.md5(str(self).encode()).digest()  # type: ignore[arg-type]

    def proto_app_version(self) -> WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.AppVersion:
        """Convert to protobuf app version - matches Go's ProtoAppVersion."""
        app_version = WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.AppVersion()
        app_version.primary = self._version[0]
        app_version.secondary = self._version[1]
        app_version.tertiary = self._version[2]
        return app_version

    def __getitem__(self, index: int) -> int:
        """Allow array-like access."""
        return self._version[index]

    # def __eq__(self, other) -> bool:
    #     """Equality comparison."""
    #     if isinstance(other, WAVersionContainer):
    #         return self._version == other._version
    #     return False


# Global WhatsApp version - matches Go's waVersion
_wa_version = WAVersionContainer(2, 3000, 1022781640)
_wa_version_hash = _wa_version.hash()


def get_wa_version() -> WAVersionContainer:
    """Get current WhatsApp web client version - matches Go's GetWAVersion."""
    return _wa_version


def set_wa_version(version: WAVersionContainer) -> None:
    """Set WhatsApp web client version - matches Go's SetWAVersion."""
    global _wa_version, _wa_version_hash
    if version.is_zero():
        return
    _wa_version = version
    _wa_version_hash = version.hash()


def get_wa_version_hash() -> bytes:
    """Get MD5 hash of current version - matches Go's waVersionHash."""
    return _wa_version_hash


# Create base client payload - matches Go's BaseClientPayload
def create_base_client_payload() -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Create base client payload exactly matching Go implementation."""
    payload = WAWebProtobufsWa6_pb2.ClientPayload()

    # Set user agent - matches Go's BaseClientPayload.UserAgent
    payload.userAgent.platform = WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.Platform.WEB
    payload.userAgent.releaseChannel = WAWebProtobufsWa6_pb2.ClientPayload.UserAgent.ReleaseChannel.RELEASE
    payload.userAgent.appVersion.CopyFrom(_wa_version.proto_app_version())
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


def get_registration_payload(device: 'Device') -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for device registration - matches Go's getRegistrationPayload."""
    # Clone the base payload - matches Go's proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    # Create registration ID bytes - matches Go's regID := make([]byte, 4); binary.BigEndian.PutUint32(regID, device.RegistrationID)
    reg_id = bytearray(4)
    struct.pack_into(">I", reg_id, 0, device.registration_id)  # type: ignore[arg-type]

    # Create pre-key ID bytes - matches Go's preKeyID := make([]byte, 4); binary.BigEndian.PutUint32(preKeyID, device.SignedPreKey.KeyID)
    pre_key_id = bytearray(4)
    struct.pack_into(">I", pre_key_id, 0, device.signed_pre_key.key_id)  # type: ignore[arg-type]

    # Marshal device props - matches Go's deviceProps, _ := proto.Marshal(DeviceProps)
    device_props_bytes = DEVICE_PROPS.SerializeToString()

    # Create device pairing data - matches Go's payload.DevicePairingData = &waWa6.ClientPayload_DevicePairingRegistrationData{...}
    device_pairing_data = WAWebProtobufsWa6_pb2.ClientPayload.DevicePairingRegistrationData()
    device_pairing_data.eRegid = bytes(reg_id)
    device_pairing_data.eKeytype = bytes([5])  # matches Go's []byte{ecc.DjbType} where DjbType = 5
    device_pairing_data.eIdent = device.identity_key.pub  # matches Go's device.IdentityKey.Pub[:]
    device_pairing_data.eSkeyID = bytes(pre_key_id[1:])  # matches Go's preKeyID[1:]
    device_pairing_data.eSkeyVal = device.signed_pre_key.pub  # matches Go's device.SignedPreKey.Pub[:]
    assert device.signed_pre_key.signature is not None
    device_pairing_data.eSkeySig = device.signed_pre_key.signature  # matches Go's device.SignedPreKey.Signature[:]
    device_pairing_data.buildHash = get_wa_version_hash()  # matches Go's waVersionHash[:]
    device_pairing_data.deviceProps = device_props_bytes

    # Set device pairing data on payload
    payload.devicePairingData.CopyFrom(device_pairing_data)

    # Set flags - matches Go's payload.Passive = proto.Bool(false); payload.Pull = proto.Bool(false)
    payload.passive = False
    payload.pull = False

    return payload


def get_login_payload(device: 'Device') -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get client payload for login - matches Go's getLoginPayload."""
    # Clone the base payload - matches Go's proto.Clone(BaseClientPayload).(*waWa6.ClientPayload)
    payload = WAWebProtobufsWa6_pb2.ClientPayload()
    payload.CopyFrom(BASE_CLIENT_PAYLOAD)

    # Set username and device - matches Go's payload.Username = proto.Uint64(device.ID.UserInt()); payload.Device = proto.Uint32(uint32(device.ID.Device))
    assert device.id is not None
    payload.username = device.id.user_int()
    payload.device = device.id.device

    # Set flags - matches Go's payload.Passive = proto.Bool(true); payload.Pull = proto.Bool(true)
    payload.passive = True
    payload.pull = True

    return payload


def get_client_payload(device: 'Device') -> WAWebProtobufsWa6_pb2.ClientPayload:
    """Get appropriate client payload based on device state - matches Go's GetClientPayload."""
    if device.id is not None:
        if device.id == EMPTY_JID:
            raise ValueError("GetClientPayload called with empty JID")
        return get_login_payload(device)
    else:
        return get_registration_payload(device)
