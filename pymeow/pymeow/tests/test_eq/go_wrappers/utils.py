"""Common utilities for Go wrappers."""

import platform
import subprocess
from pathlib import Path
from typing import Optional


def get_lib_path(lib_name: Optional[str] = None) -> Path:
    """Get the path to the Go shared library.
    Attempts to build it if not found.

    Args:
        lib_name: Optional name of the library. If None, the default library name is used.

    Returns:
        Path to the shared library.

    Raises:
        OSError: If the library cannot be found or built.
    """
    system = platform.system()
    if lib_name is None:
        if system == "Windows":
            lib_name = "libwhatsmeow.dll"
        elif system == "Linux":
            lib_name = "libwhatsmeow.so"
        # Add macOS support if needed:
        # elif system == "Darwin":
        #     lib_name = "libwhatsmeow.dylib"
        else:
            raise OSError(f"Unsupported operating system for Go wrapper: {system}")

    # Determine the go_test_helpers directory relative to this file
    # ../../../../../go_test_helpers
    go_helpers_dir = (Path(__file__).parent.parent.parent.parent.parent / "go_test_helpers").resolve()
    lib_path = go_helpers_dir / "bin" / lib_name

    if not lib_path.exists():
        print(f"Shared library not found at {lib_path}. Attempting to build...")

        build_script_name = "build_go.bat" if system == "Windows" else "build_go.sh"
        build_script_path = go_helpers_dir / build_script_name

        if not build_script_path.exists():
            raise OSError(
                f"Build script {build_script_name} not found in {go_helpers_dir}. Cannot build the library {lib_name}."
            )

        try:
            command_to_run = []
            if system == "Windows":
                command_to_run = [str(build_script_path), "build"]
            else:  # Linux, macOS
                # Ensure the script is executable
                subprocess.run(["chmod", "+x", str(build_script_path)], check=True, cwd=str(go_helpers_dir))
                command_to_run = [f"./{build_script_name}", "build"]

            print(f"Running build script: {' '.join(command_to_run)} in {go_helpers_dir}")
            subprocess.run(command_to_run, check=True, cwd=str(go_helpers_dir), capture_output=True, text=True)
            print(f"Build successful. Library should be at {lib_path}")

            # Verify the library exists after build
            if not lib_path.exists():
                raise OSError(
                    f"Build script ran but the library {lib_path} was not created. "
                    "Check build script output and Go environment."
                )

        except subprocess.CalledProcessError as e:
            error_message = f"Error building shared library using {build_script_name}: {e}\n"
            error_message += f"Stdout: {e.stdout}\n"
            error_message += f"Stderr: {e.stderr}\n"
            print(error_message)
            raise OSError(
                f"Failed to build the Go shared library at {lib_path}. "
                "Please build it manually using the script in go_test_helpers."
            )
        except FileNotFoundError:  # Should be caught by build_script_path.exists() check, but as a fallback
            raise OSError(f"Build script {build_script_name} not found in {go_helpers_dir}. Cannot build the library.")
        except Exception as e:  # Catch any other unexpected errors during the build process
            raise OSError(f"An unexpected error occurred while trying to build {lib_path}: {e}")

    # Final check, even if it existed before or was just built
    if not lib_path.exists():
        raise OSError(
            f"Go shared library not found at {lib_path} after all attempts. Please check the path and build process."
        )

    return lib_path
