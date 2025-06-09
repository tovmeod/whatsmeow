#!/usr/bin/env python3
import os
import re
from pathlib import Path


def fix_imports_in_file(file_path: Path):
    """Fix import statements in a generated protobuf file."""
    if not file_path.exists() or not file_path.is_file():
        return

    print(f"Fixing imports in {file_path}")

    content = file_path.read_text()

    # Fix imports like 'import waAdv.WAAdv_pb2 as waAdv_dot_WAAdv__pb2'
    content = re.sub(
        r'import\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+_pb2)\s+as\s+\w+_dot_\w+__pb2',
        r'from . import \1.\2 as \1_dot_\2',
        content
    )

    # Fix remaining absolute imports
    content = re.sub(
        r'^import\s+([a-zA-Z0-9_]+)\.',
        r'from . import \1.',
        content,
        flags=re.MULTILINE
    )

    # Fix references to the fixed imports
    content = re.sub(
        r'([a-zA-Z0-9_]+)_dot_([a-zA-Z0-9_]+)__pb2\.',
        r'\1.\2_pb2.',
        content
    )

    file_path.write_text(content)

def main():
    project_root = Path(__file__).parent.parent
    generated_dir = project_root / 'pymeow' / 'generated'

    # Process all Python files in the generated directory
    for py_file in generated_dir.rglob('*.py'):
        fix_imports_in_file(py_file)

    # Ensure all directories have __init__.py
    for root, dirs, _ in os.walk(generated_dir):
        for dir_name in dirs:
            init_file = Path(root) / dir_name / '__init__.py'
            if not init_file.exists():
                init_file.write_text('# Generated protocol buffer classes\n')

if __name__ == '__main__':
    main()
