from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class QP(_message.Message):
    __slots__ = ()
    class FilterResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        TRUE: _ClassVar[QP.FilterResult]
        FALSE: _ClassVar[QP.FilterResult]
        UNKNOWN: _ClassVar[QP.FilterResult]
    TRUE: QP.FilterResult
    FALSE: QP.FilterResult
    UNKNOWN: QP.FilterResult
    class FilterClientNotSupportedConfig(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        PASS_BY_DEFAULT: _ClassVar[QP.FilterClientNotSupportedConfig]
        FAIL_BY_DEFAULT: _ClassVar[QP.FilterClientNotSupportedConfig]
    PASS_BY_DEFAULT: QP.FilterClientNotSupportedConfig
    FAIL_BY_DEFAULT: QP.FilterClientNotSupportedConfig
    class ClauseType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        AND: _ClassVar[QP.ClauseType]
        OR: _ClassVar[QP.ClauseType]
        NOR: _ClassVar[QP.ClauseType]
    AND: QP.ClauseType
    OR: QP.ClauseType
    NOR: QP.ClauseType
    class FilterClause(_message.Message):
        __slots__ = ("clauseType", "clauses", "filters")
        CLAUSETYPE_FIELD_NUMBER: _ClassVar[int]
        CLAUSES_FIELD_NUMBER: _ClassVar[int]
        FILTERS_FIELD_NUMBER: _ClassVar[int]
        clauseType: QP.ClauseType
        clauses: _containers.RepeatedCompositeFieldContainer[QP.FilterClause]
        filters: _containers.RepeatedCompositeFieldContainer[QP.Filter]
        def __init__(self, clauseType: _Optional[_Union[QP.ClauseType, str]] = ..., clauses: _Optional[_Iterable[_Union[QP.FilterClause, _Mapping]]] = ..., filters: _Optional[_Iterable[_Union[QP.Filter, _Mapping]]] = ...) -> None: ...
    class Filter(_message.Message):
        __slots__ = ("filterName", "parameters", "filterResult", "clientNotSupportedConfig")
        FILTERNAME_FIELD_NUMBER: _ClassVar[int]
        PARAMETERS_FIELD_NUMBER: _ClassVar[int]
        FILTERRESULT_FIELD_NUMBER: _ClassVar[int]
        CLIENTNOTSUPPORTEDCONFIG_FIELD_NUMBER: _ClassVar[int]
        filterName: str
        parameters: _containers.RepeatedCompositeFieldContainer[QP.FilterParameters]
        filterResult: QP.FilterResult
        clientNotSupportedConfig: QP.FilterClientNotSupportedConfig
        def __init__(self, filterName: _Optional[str] = ..., parameters: _Optional[_Iterable[_Union[QP.FilterParameters, _Mapping]]] = ..., filterResult: _Optional[_Union[QP.FilterResult, str]] = ..., clientNotSupportedConfig: _Optional[_Union[QP.FilterClientNotSupportedConfig, str]] = ...) -> None: ...
    class FilterParameters(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    def __init__(self) -> None: ...
