"""
Binary encoder wrapper for whatsmeow Go library.
This module provides Python bindings for whatsmeow's binary encoding functionality.
"""

import ctypes
import json
from typing import Dict, Any
from ..utils import get_lib_path


class GoLibraryError(Exception):
    """Exception raised when Go library operations fail."""
    pass


class GoLibrary:
    """Singleton for managing the Go shared library."""

    _instance = None
    _lib = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._lib is None:
            try:
                lib_path = get_lib_path()
                self._lib = ctypes.CDLL(str(lib_path))

                if not hasattr(self._lib, 'call_method'):
                    available_funcs = [name for name in dir(self._lib) if not name.startswith('_')]
                    raise GoLibraryError(f"Function 'call_method' not found in library. Available functions: {available_funcs}")

                self._lib.call_method.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                self._lib.call_method.restype = ctypes.c_char_p

            except Exception as e:
                raise GoLibraryError(f"Failed to load Go library: {e}")

    def call_method(self, method: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Go method with JSON arguments."""
        if not self._lib:
            raise GoLibraryError("Go library not initialized")

        try:
            method_bytes = method.encode('utf-8')
            args_json = json.dumps(args).encode('utf-8')

            result_ptr = self._lib.call_method(method_bytes, args_json)

            if not result_ptr:
                raise GoLibraryError("Go function returned null pointer")

            result_str = ctypes.string_at(result_ptr).decode('utf-8')
            return json.loads(result_str)

        except Exception as e:
            raise GoLibraryError(f"Error calling Go method '{method}': {e}") from e


def write_node_get_data(node: Dict[str, Any]) -> bytes:
    """Write node and get data using Go's binary.Marshal (equivalent to encoder.writeNode().getData())."""
    go_lib = GoLibrary()
    result = go_lib.call_method('binary.encoder.writeNodeGetData', {'node': node})

    if 'error' in result:
        raise GoLibraryError(f"Encode failed: {result['error']}")

    hex_data = result.get('data', '')
    if not hex_data:
        raise GoLibraryError("No data returned from encode operation")

    try:
        return bytes.fromhex(hex_data)
    except ValueError as e:
        raise GoLibraryError(f"Invalid hex data returned from encode: {hex_data}") from e
