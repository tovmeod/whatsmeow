#!/usr/bin/env python3
import os
import re
from pathlib import Path

def fix_imports_in_file(file_path: Path):
    """Fix import statements in a generated protobuf file."""
    if not file_path.exists() or not file_path.is_file() or not file_path.suffix == '.py':
        return False
    
    print(f"Processing {file_path}")
    
    try:
        content = file_path.read_text()
        modified = False
        
        # Fix imports like 'import waAdv.WAAdv_pb2 as waAdv_dot_WAAdv__pb2'
        new_content = re.sub(
            r'^import\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+_pb2)\s+as\s+\w+_dot_\w+__pb2',
            r'from . import \1.\2 as \1_dot_\2',
            content,
            flags=re.MULTILINE
        )
        
        # Fix remaining absolute imports
        new_content = re.sub(
            r'^import\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+_pb2)',
            r'from . import \1.\2',
            new_content,
            flags=re.MULTILINE
        )
        
        # Fix references to the fixed imports
        new_content = re.sub(
            r'([a-zA-Z0-9_]+)_dot_([a-zA-Z0-9_]+)__pb2\.',
            r'\1.\2_pb2.',
            new_content
        )
        
        if new_content != content:
            file_path.write_text(new_content)
            print(f"  ✓ Fixed imports in {file_path.name}")
            return True
            
    except Exception as e:
        print(f"  ✗ Error processing {file_path}: {e}")
    
    return False

def ensure_init_files(directory: Path):
    """Ensure all directories have __init__.py files."""
    for root, dirs, _ in os.walk(directory):
        for dir_name in dirs:
            if dir_name == '__pycache__':
                continue
                
            init_file = Path(root) / dir_name / '__init__.py'
            if not init_file.exists():
                init_file.write_text('# Generated protocol buffer classes\n')
                print(f"Created {init_file}")

def main():
    project_root = Path(__file__).parent
    generated_dir = project_root / 'pymeow' / 'pymeow' / 'generated'
    
    if not generated_dir.exists():
        print(f"Error: Directory not found: {generated_dir}")
        return
    
    print(f"Fixing imports in {generated_dir}")
    
    # First, ensure all directories have __init__.py files
    ensure_init_files(generated_dir)
    
    # Process all Python files in the generated directory
    modified_count = 0
    for py_file in generated_dir.rglob('*.py'):
        if fix_imports_in_file(py_file):
            modified_count += 1
    
    print(f"\nDone! Modified {modified_count} files.")

if __name__ == '__main__':
    main()
