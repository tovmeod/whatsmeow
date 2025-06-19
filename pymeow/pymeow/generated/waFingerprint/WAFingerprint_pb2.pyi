from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HostedState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    E2EE: _ClassVar[HostedState]
    HOSTED: _ClassVar[HostedState]
E2EE: HostedState
HOSTED: HostedState

class FingerprintData(_message.Message):
    __slots__ = ("publicKey", "pnIdentifier", "lidIdentifier", "usernameIdentifier", "hostedState", "hashedPublicKey")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    PNIDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    LIDIDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    USERNAMEIDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    HOSTEDSTATE_FIELD_NUMBER: _ClassVar[int]
    HASHEDPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    pnIdentifier: bytes
    lidIdentifier: bytes
    usernameIdentifier: bytes
    hostedState: HostedState
    hashedPublicKey: bytes
    def __init__(self, publicKey: _Optional[bytes] = ..., pnIdentifier: _Optional[bytes] = ..., lidIdentifier: _Optional[bytes] = ..., usernameIdentifier: _Optional[bytes] = ..., hostedState: _Optional[_Union[HostedState, str]] = ..., hashedPublicKey: _Optional[bytes] = ...) -> None: ...

class CombinedFingerprint(_message.Message):
    __slots__ = ("version", "localFingerprint", "remoteFingerprint")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    LOCALFINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    REMOTEFINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    version: int
    localFingerprint: FingerprintData
    remoteFingerprint: FingerprintData
    def __init__(self, version: _Optional[int] = ..., localFingerprint: _Optional[_Union[FingerprintData, _Mapping]] = ..., remoteFingerprint: _Optional[_Union[FingerprintData, _Mapping]] = ...) -> None: ...
