from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class UserPassword(_message.Message):
    __slots__ = ("encoding", "transformer", "transformerArg", "transformedData")
    class Transformer(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[UserPassword.Transformer]
        PBKDF2_HMAC_SHA512: _ClassVar[UserPassword.Transformer]
        PBKDF2_HMAC_SHA384: _ClassVar[UserPassword.Transformer]
    NONE: UserPassword.Transformer
    PBKDF2_HMAC_SHA512: UserPassword.Transformer
    PBKDF2_HMAC_SHA384: UserPassword.Transformer
    class Encoding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UTF8: _ClassVar[UserPassword.Encoding]
        UTF8_BROKEN: _ClassVar[UserPassword.Encoding]
    UTF8: UserPassword.Encoding
    UTF8_BROKEN: UserPassword.Encoding
    class TransformerArg(_message.Message):
        __slots__ = ("key", "value")
        class Value(_message.Message):
            __slots__ = ("asBlob", "asUnsignedInteger")
            ASBLOB_FIELD_NUMBER: _ClassVar[int]
            ASUNSIGNEDINTEGER_FIELD_NUMBER: _ClassVar[int]
            asBlob: bytes
            asUnsignedInteger: int
            def __init__(self, asBlob: _Optional[bytes] = ..., asUnsignedInteger: _Optional[int] = ...) -> None: ...
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: UserPassword.TransformerArg.Value
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[UserPassword.TransformerArg.Value, _Mapping]] = ...) -> None: ...
    ENCODING_FIELD_NUMBER: _ClassVar[int]
    TRANSFORMER_FIELD_NUMBER: _ClassVar[int]
    TRANSFORMERARG_FIELD_NUMBER: _ClassVar[int]
    TRANSFORMEDDATA_FIELD_NUMBER: _ClassVar[int]
    encoding: UserPassword.Encoding
    transformer: UserPassword.Transformer
    transformerArg: _containers.RepeatedCompositeFieldContainer[UserPassword.TransformerArg]
    transformedData: bytes
    def __init__(self, encoding: _Optional[_Union[UserPassword.Encoding, str]] = ..., transformer: _Optional[_Union[UserPassword.Transformer, str]] = ..., transformerArg: _Optional[_Iterable[_Union[UserPassword.TransformerArg, _Mapping]]] = ..., transformedData: _Optional[bytes] = ...) -> None: ...
