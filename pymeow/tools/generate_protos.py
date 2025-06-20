#!/usr/bin/env python3
import subprocess
import re
from pathlib import Path


def generate_protos():
    project_root = Path(__file__).parent.parent.parent
    proto_dir = project_root / 'proto'
    output_dir = project_root / 'pymeow' / 'pymeow' / 'generated'

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Simple protoc command
    cmd = [
        'protoc',
        f'--proto_path={proto_dir}',
        f'--python_out={output_dir}',
        f'--pyi_out={output_dir}',  # This generates proper mypy stubs
    ]

    # Add all proto files
    proto_files = list(proto_dir.rglob('*.proto'))
    cmd.extend(str(f) for f in proto_files)

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("✓ Generated protobuf files successfully")
        # Now fix the imports
        fix_imports(output_dir)
    else:
        print("✗ Error generating protobuf files:")
        print(result.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd)


def fix_imports(output_dir):
    """Fix absolute imports to relative imports in generated protobuf files."""
    print("🔧 Fixing imports in generated protobuf files...")

    fixed_count = 0
    for pb2_file in output_dir.rglob("*_pb2.py"):
        try:
            with open(pb2_file, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content

            # Fix imports from waXXX modules to relative imports
            # Pattern: from waXXX import YYY_pb2 as zzz
            content = re.sub(
                r'from (wa\w+) import (\w+_pb2) as (\w+)',
                r'from ..\1 import \2 as \3',
                content
            )

            # Pattern: from waXXX import YYY_pb2
            content = re.sub(
                r'from (wa\w+) import (\w+_pb2)',
                r'from ..\1 import \2',
                content
            )

            # Also fix any import waXXX.YYY patterns
            content = re.sub(
                r'import (wa\w+)\.(\w+_pb2)',
                r'from .. import \1.\2',
                content
            )

            if content != original_content:
                print(f"  Fixed imports in {pb2_file.relative_to(output_dir.parent.parent.parent)}")
                with open(pb2_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                fixed_count += 1

        except Exception as e:
            print(f"    ⚠️  Warning: Could not fix imports in {pb2_file}: {e}")

    print(f"✓ Fixed imports in {fixed_count} files")


if __name__ == '__main__':
    generate_protos()
