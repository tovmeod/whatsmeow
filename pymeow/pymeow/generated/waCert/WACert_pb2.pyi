from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class NoiseCertificate(_message.Message):
    __slots__ = ("details", "signature")
    class Details(_message.Message):
        __slots__ = ("serial", "issuer", "expires", "subject", "key")
        SERIAL_FIELD_NUMBER: _ClassVar[int]
        ISSUER_FIELD_NUMBER: _ClassVar[int]
        EXPIRES_FIELD_NUMBER: _ClassVar[int]
        SUBJECT_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        serial: int
        issuer: str
        expires: int
        subject: str
        key: bytes
        def __init__(self, serial: _Optional[int] = ..., issuer: _Optional[str] = ..., expires: _Optional[int] = ..., subject: _Optional[str] = ..., key: _Optional[bytes] = ...) -> None: ...
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    details: bytes
    signature: bytes
    def __init__(self, details: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class CertChain(_message.Message):
    __slots__ = ("leaf", "intermediate")
    class NoiseCertificate(_message.Message):
        __slots__ = ("details", "signature")
        class Details(_message.Message):
            __slots__ = ("serial", "issuerSerial", "key", "notBefore", "notAfter")
            SERIAL_FIELD_NUMBER: _ClassVar[int]
            ISSUERSERIAL_FIELD_NUMBER: _ClassVar[int]
            KEY_FIELD_NUMBER: _ClassVar[int]
            NOTBEFORE_FIELD_NUMBER: _ClassVar[int]
            NOTAFTER_FIELD_NUMBER: _ClassVar[int]
            serial: int
            issuerSerial: int
            key: bytes
            notBefore: int
            notAfter: int
            def __init__(self, serial: _Optional[int] = ..., issuerSerial: _Optional[int] = ..., key: _Optional[bytes] = ..., notBefore: _Optional[int] = ..., notAfter: _Optional[int] = ...) -> None: ...
        DETAILS_FIELD_NUMBER: _ClassVar[int]
        SIGNATURE_FIELD_NUMBER: _ClassVar[int]
        details: bytes
        signature: bytes
        def __init__(self, details: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...
    LEAF_FIELD_NUMBER: _ClassVar[int]
    INTERMEDIATE_FIELD_NUMBER: _ClassVar[int]
    leaf: CertChain.NoiseCertificate
    intermediate: CertChain.NoiseCertificate
    def __init__(self, leaf: _Optional[_Union[CertChain.NoiseCertificate, _Mapping]] = ..., intermediate: _Optional[_Union[CertChain.NoiseCertificate, _Mapping]] = ...) -> None: ...
