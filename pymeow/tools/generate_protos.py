# !/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path


def generate_protos() -> None:
    project_root = Path(__file__).parent.parent.parent
    proto_dir = project_root / "proto"
    output_dir = project_root / "pymeow" / "pymeow" / "generated"

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Simple protoc command
    cmd = [
        "protoc",
        f"--proto_path={proto_dir}",
        f"--python_out={output_dir}",
        f"--pyi_out={output_dir}",  # This generates proper mypy stubs
    ]

    # Add all proto files
    proto_files = list(proto_dir.rglob("*.proto"))
    cmd.extend(str(f) for f in proto_files)

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("✓ Generated protobuf files successfully")
        # Now fix the imports in both .py and .pyi files
        fix_imports(output_dir)
        # Ensure all directories have __init__.py files
        ensure_init_files(output_dir)
    else:
        print("✗ Error generating protobuf files:")
        print(result.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd)


def fix_imports(output_dir: Path) -> None:
    """Fix absolute imports to relative imports in generated protobuf files."""
    print("🔧 Fixing imports in generated protobuf files...")

    fixed_count = 0

    # Process both .py and .pyi files
    for file_pattern in ["*_pb2.py", "*_pb2.pyi"]:
        for pb2_file in output_dir.rglob(file_pattern):
            try:
                with open(pb2_file, "r", encoding="utf-8") as f:
                    content = f.read()

                original_content = content

                # Fix different import patterns that protoc generates
                # Use two dots (..) to go from waXXX/ to sibling waYYY/ directory

                # Pattern 1: from waXXX import YYY_pb2 as ZZZ
                content = re.sub(
                    r"^from\s+(wa\w+)\s+import\s+(\w+_pb2)\s+as\s+(\w+)",
                    r"from ..\1 import \2 as \3",
                    content,
                    flags=re.MULTILINE
                )

                # Pattern 2: from waXXX import YYY_pb2
                content = re.sub(
                    r"^from\s+(wa\w+)\s+import\s+(\w+_pb2)",
                    r"from ..\1 import \2",
                    content,
                    flags=re.MULTILINE
                )

                # Pattern 3: import waXXX.YYY_pb2 as ZZZ
                content = re.sub(
                    r"^import\s+(wa\w+)\.(\w+_pb2)\s+as\s+(\w+)",
                    r"from ..\1 import \2 as \3",
                    content,
                    flags=re.MULTILINE
                )

                # Pattern 4: import waXXX.YYY_pb2
                content = re.sub(
                    r"^import\s+(wa\w+)\.(\w+_pb2)",
                    r"from ..\1 import \2",
                    content,
                    flags=re.MULTILINE
                )

                # Pattern 5: import waXXX (standalone module import)
                content = re.sub(
                    r"^import\s+(wa\w+)$",
                    r"from .. import \1",
                    content,
                    flags=re.MULTILINE
                )

                if content != original_content:
                    print(f"  Fixed imports in {pb2_file.relative_to(output_dir.parent.parent.parent)}")
                    with open(pb2_file, "w", encoding="utf-8") as f:
                        f.write(content)
                    fixed_count += 1

            except Exception as e:
                print(f"    ⚠️  Warning: Could not fix imports in {pb2_file}: {e}")

    print(f"✓ Fixed imports in {fixed_count} files")


def ensure_init_files(output_dir: Path) -> None:
    """Ensure all directories have __init__.py files."""
    print("📁 Ensuring __init__.py files exist...")

    created_count = 0
    for root, dirs, _ in os.walk(output_dir):
        for dir_name in dirs:
            if dir_name == "__pycache__":
                continue

            init_file = Path(root) / dir_name / "__init__.py"
            if not init_file.exists():
                init_file.write_text("# Generated protocol buffer classes\n")
                print(f"  Created {init_file.relative_to(output_dir.parent.parent.parent)}")
                created_count += 1

    if created_count > 0:
        print(f"✓ Created {created_count} __init__.py files")
    else:
        print("✓ All __init__.py files already exist")


if __name__ == "__main__":
    generate_protos()
