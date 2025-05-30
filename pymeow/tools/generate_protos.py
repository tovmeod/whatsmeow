#!/usr/bin/env python3
import os
import re
import subprocess
import sys
from pathlib import Path
import shutil

def find_protoc():
    """Find protoc executable, preferring grpcio-tools version."""
    # First try to use protoc from grpcio-tools
    try:
        import grpc_tools.protoc as protoc_module
        # grpcio-tools provides protoc via python -m grpc_tools.protoc
        return [sys.executable, "-m", "grpc_tools.protoc"]
    except ImportError:
        print("⚠ grpcio-tools not found, trying system protoc...")

    # Fallback to system protoc
    if shutil.which('protoc'):
        return ['protoc']

    # No protoc found
    print("❌ Protocol Buffer compiler (protoc) not found!")
    print("\nOptions to install protoc:")
    print("1. Install grpcio-tools: uv add grpcio-tools")
    print("2. Using winget: winget install protocolbuffers.protoc")
    print("3. Using chocolatey: choco install protoc")
    print("4. Manual download from: https://github.com/protocolbuffers/protobuf/releases")
    print("\nAfter installation, restart your terminal and try again.")
    sys.exit(1)

def check_protoc_available():
    """Check if protoc is available and provide helpful error message if not."""
    protoc_cmd = find_protoc()

    # Check protoc version
    try:
        result = subprocess.run(protoc_cmd + ['--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Found protoc: {result.stdout.strip()}")
            return protoc_cmd
        else:
            print("⚠ protoc found but version check failed")
            return protoc_cmd
    except Exception as e:
        print(f"⚠ Error checking protoc version: {e}")
        return protoc_cmd

def ensure_directory(path):
    """Ensure directory exists and has __init__.py"""
    path.mkdir(parents=True, exist_ok=True)
    init_file = path / '__init__.py'
    if not init_file.exists():
        init_file.write_text('# Generated protocol buffer classes\n')

def fix_imports(file_path: Path):
    """Fix import statements in generated protobuf files to use relative imports."""
    if not file_path.exists():
        return

    content = file_path.read_text(encoding='utf-8')

    # For Python files (.py)
    if file_path.suffix == '.py':
        # Fix imports like 'import waCommon.WACommon_pb2 as waCommon_dot_WACommon__pb2'
        content = re.sub(
            r'^import\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+_pb2)\s+as\s+([a-zA-Z0-9_]+_dot_[a-zA-Z0-9_]+__pb2)',
            r'from ..\1 import \2 as \3',
            content,
            flags=re.MULTILINE
        )

        # Fix direct imports like 'from waCommon import WACommon_pb2'
        content = re.sub(
            r'^from\s+([a-zA-Z0-9_]+)\s+import\s+([a-zA-Z0-9_]+_pb2)',
            r'from ..\1 import \2',
            content,
            flags=re.MULTILINE
        )

    # For mypy stub files (.pyi)
    elif file_path.suffix == '.pyi':
        # Fix imports in the form 'from waCommon.WACommon_pb2 import ...'
        content = re.sub(
            r'^from\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+_pb2)\s+import',
            r'from ..\1.\2 import',
            content,
            flags=re.MULTILINE
        )

    # Fix imports that reference the fixed imports (for both .py and .pyi)
    content = re.sub(
        r'([a-zA-Z0-9_]+_dot_[a-zA-Z0-9_]+)__pb2\.',
        r'\1_pb2.',
        content
    )

    file_path.write_text(content, encoding='utf-8')

def generate_protos():
    # Check if protoc is available and get the command
    protoc_cmd = check_protoc_available()

    project_root = Path(__file__).parent.parent.parent
    proto_dir = project_root / 'proto'
    output_dir = project_root / 'pymeow' / 'pymeow' / 'generated'

    # Ensure base output directory exists
    ensure_directory(output_dir)

    # Find all .proto files
    proto_files = []
    for root, _, files in os.walk(proto_dir):
        for file in files:
            if file.endswith('.proto'):
                proto_files.append(Path(root) / file)

    if not proto_files:
        print(f"❌ No .proto files found in {proto_dir}")
        return

    print(f"Found {len(proto_files)} .proto files to process")

    # Generate Python code for each .proto file
    success_count = 0
    for proto_file in proto_files:
        rel_path = proto_file.relative_to(project_root)
        print(f"Generating Python code for {rel_path}")

        # Create output subdirectory matching the proto file structure
        package_dir = output_dir / proto_file.parent.relative_to(proto_dir)
        ensure_directory(package_dir)

        try:
            # Base protoc command - use absolute paths on Windows
            base_cmd = protoc_cmd + [
                f'--proto_path={proto_dir.absolute()}',
                f'--python_out={output_dir.absolute()}',
                f'--descriptor_set_out={output_dir.absolute()}/descriptor.pb',
                '--include_imports',
                '--include_source_info',
                str(proto_file.absolute())
            ]

            # Try to run base protoc command
            result = subprocess.run(base_cmd, capture_output=True, text=True, cwd=project_root)

            if result.returncode != 0:
                print(f"✗ Error generating {rel_path}:")
                print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
                print("Command:", ' '.join(base_cmd))
                continue

            print(f"✓ Generated {rel_path}")
            success_count += 1

            # Try to generate mypy stubs if mypy-protobuf is available
            try:
                import mypy_protobuf
                mypy_cmd = protoc_cmd + [
                    f'--proto_path={proto_dir.absolute()}',
                    f'--python_out={output_dir.absolute()}',
                    f'--mypy_out={output_dir.absolute()}',
                    '--mypy_opt=readable_stubs',
                    str(proto_file.absolute())
                ]
                mypy_result = subprocess.run(mypy_cmd, capture_output=True, text=True, cwd=project_root)
                if mypy_result.returncode == 0:
                    print(f"✓ Generated mypy stubs for {rel_path}")
                else:
                    print(f"⚠ Could not generate mypy stubs for {rel_path}")
                    if mypy_result.stderr:
                        print("STDERR:", mypy_result.stderr)
            except ImportError:
                print(f"⚠ mypy-protobuf not found, skipping mypy stubs for {rel_path}")
            except Exception as e:
                print(f"⚠ Could not generate mypy stubs for {rel_path}: {e}")

            # Fix imports in the generated files
            proto_name = proto_file.stem
            py_file = package_dir / f"{proto_name}_pb2.py"
            if py_file.exists():
                fix_imports(py_file)
                print(f"✓ Fixed imports in {py_file.relative_to(project_root)}")

            # Also fix the mypy stub file if it exists
            pyi_file = package_dir / f"{proto_name}_pb2.pyi"
            if pyi_file.exists():
                fix_imports(pyi_file)
                print(f"✓ Fixed imports in {pyi_file.relative_to(project_root)}")

        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to generate {rel_path}: {e}")
            continue
        except Exception as e:
            print(f"✗ Unexpected error generating {rel_path}: {e}")
            continue

    # Create proper __init__.py files in all subdirectories
    for root, dirs, _ in os.walk(output_dir):
        for dir_name in dirs:
            init_file = Path(root) / dir_name / '__init__.py'
            if not init_file.exists():
                init_file.write_text('# Generated protocol buffer classes\n')

    print(f"\n✓ Successfully generated {success_count}/{len(proto_files)} proto files")

    if success_count < len(proto_files):
        print("⚠ Some proto files failed to generate. Check the errors above.")
        sys.exit(1)

if __name__ == '__main__':
    generate_protos()
