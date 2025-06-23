"""Common utilities for Go wrappers."""

import platform
from pathlib import Path
from typing import Optional


def get_lib_path(lib_name: Optional[str] = None) -> Path:
    """Get the path to the Go shared library.

    Args:
        lib_name: Optional name of the library. If None, the default library name is used.

    Returns:
        Path to the shared library.
    """
    if lib_name is None:
        lib_name = "libwhatsmeow.dll" if platform.system() == "Windows" else "libwhatsmeow.so"

    # Navigate up from this file to the bin directory
    bin_dir = Path(__file__).parent.parent.parent.parent.parent / "go_test_helpers" / "bin"
    lib_path = bin_dir / lib_name

    if not lib_path.exists():
        raise FileNotFoundError(f"Go shared library not found at {lib_path}. Please build it first.")

    return lib_path
