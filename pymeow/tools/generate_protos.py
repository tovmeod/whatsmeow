#!/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path

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
        
    content = file_path.read_text()
    
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
    
    file_path.write_text(content)

def generate_protos():
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

    # Generate Python code for each .proto file
    for proto_file in proto_files:
        rel_path = proto_file.relative_to(project_root)
        print(f"Generating Python code for {rel_path}")

        # Create output subdirectory matching the proto file structure
        package_dir = output_dir / proto_file.parent.relative_to(proto_dir)
        ensure_directory(package_dir)

        try:
            # Base protoc command
            base_cmd = [
                'protoc',
                f'--proto_path={proto_dir}',
                f'--python_out={output_dir}',
                f'--descriptor_set_out={output_dir}/descriptor.pb',
                '--include_imports',
                '--include_source_info',
                str(proto_file)
            ]
            
            # Try to run base protoc command
            result = subprocess.run(base_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"✗ Error generating {rel_path}:")
                print(result.stderr)
                continue
                
            print(f"✓ Generated {rel_path}")
            
            # Try to generate mypy stubs if protoc-gen-mypy is available
            try:
                mypy_cmd = base_cmd.copy()
                # Insert mypy_out after python_out
                mypy_cmd.insert(3, f'--mypy_out={output_dir}')
                mypy_cmd.insert(3, '--mypy_opt=readable_stubs')
                mypy_result = subprocess.run(mypy_cmd, capture_output=True, text=True)
                if mypy_result.returncode == 0:
                    print(f"✓ Generated mypy stubs for {rel_path}")
                else:
                    print(f"⚠ Could not generate mypy stubs for {rel_path} (protoc-gen-mypy not found or failed)")
                    print(mypy_result.stderr)
            except Exception as e:
                print(f"⚠ Could not generate mypy stubs for {rel_path}: {e}")
            
            # Fix imports in the generated files
            proto_name = proto_file.stem
            py_file = package_dir / f"{proto_name}_pb2.py"
            if py_file.exists():
                fix_imports(py_file)
            
            # Also fix the mypy stub file if it exists
            pyi_file = package_dir / f"{proto_name}_pb2.pyi"
            if pyi_file.exists():
                fix_imports(pyi_file)

        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to generate {rel_path}: {e}")
            raise

    # Create proper __init__.py files in all subdirectories
    for root, dirs, _ in os.walk(output_dir):
        for dir_name in dirs:
            init_file = Path(root) / dir_name / '__init__.py'
            if not init_file.exists():
                init_file.write_text('# Generated protocol buffer classes\n')

if __name__ == '__main__':
    generate_protos()
