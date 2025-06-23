"""
Binary decoder wrapper for whatsmeow Go library.
This module provides Python bindings for whatsmeow's binary decoding functionality.
"""

from typing import Any, Dict

from .encoder import GoLibrary, GoLibraryError


def unmarshal(data: bytes) -> Dict[str, Any]:
    """Unmarshal binary data to node using Go's binary.Unmarshal."""
    go_lib = GoLibrary()
    hex_data = data.hex()
    result = go_lib.call_method("binary.decoder.unmarshal", {"data": hex_data})

    if "error" in result:
        raise GoLibraryError(f"Decode failed: {result['error']}")

    node_data = result.get("node")
    if not node_data:
        raise GoLibraryError("No node data returned from decode operation")

    return node_data
