#!/usr/bin/env python3
import os
import re
from collections import defaultdict
from pathlib import Path

# Define the project root
PROJECT_ROOT = Path(__file__).parent.absolute()

# Define the output file
OUTPUT_FILE = PROJECT_ROOT / "DEPENDENCIES.md"

# Define the main sections and their paths
SECTIONS = {
    "Core Components": ["*.go"],
    "Binary Protocol": ["binary/*.go"],
    "Store Implementation": ["store/*.go", "store/*/*.go"],
    "Application State": ["appstate/*.go", "appstate/*/*.go"],
    "Socket Implementation": ["socket/*.go"],
    "Types": ["types/*.go", "types/*/*.go"],
    "Utils": ["util/*.go", "util/*/*.go"],
}

def parse_imports(file_path):
    """Parse imports from a Go file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all import blocks
    import_blocks = re.findall(r'import\s*\((.*?)\)', content, re.DOTALL)
    if not import_blocks:
        # Look for single-line imports
        single_imports = re.findall(r'import\s+[\"\'](.*?)[\"\']', content)
        return single_imports
    
    imports = []
    for block in import_blocks:
        # Split by newlines and clean up
        lines = [line.strip() for line in block.split('\n')]
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            # Handle aliased imports
            if ' ' in line:
                line = line.split(' ')[-1]
            # Remove quotes
            line = line.strip('"')
            if line:
                imports.append(line)
    
    return imports

def get_go_files():
    """Get all Go files in the project."""
    go_files = []
    for root, _, files in os.walk(PROJECT_ROOT):
        # Skip hidden directories and vendor directory
        if '/.' in root or '/vendor/' in root or '/pymeow/' in root:
            continue
        for file in files:
            if file.endswith('.go'):
                go_files.append(Path(root) / file)
    return go_files

def analyze_dependencies():
    """Analyze dependencies between Go files."""
    files = get_go_files()
    dependencies = {}
    
    for file in files:
        rel_path = file.relative_to(PROJECT_ROOT)
        imports = parse_imports(file)
        
        # Filter out standard library and external dependencies
        internal_deps = [
            imp for imp in imports 
            if imp.startswith('go.mau.fi/whatsmeow/') and not 'vendor' in imp
        ]
        
        # Convert to relative paths
        rel_deps = []
        for dep in internal_deps:
            # Extract path after 'go.mau.fi/whatsmeow/'
            rel_path_dep = dep.replace('go.mau.fi/whatsmeow/', '')
            # Handle proto files
            if rel_path_dep.startswith('proto/'):
                rel_path_dep = 'proto/'
            rel_deps.append(rel_path_dep)
        
        dependencies[str(rel_path)] = rel_deps
    
    return dependencies

def generate_markdown(dependencies):
    """Generate markdown documentation from dependencies."""
    markdown = ["# Go File Dependencies\n"]
    
    # Group by directory
    dirs = defaultdict(dict)
    for file, deps in dependencies.items():
        dir_name = os.path.dirname(file)
        dirs[dir_name][file] = deps
    
    # Sort directories and files
    for dir_name in sorted(dirs.keys()):
        if dir_name == '.':
            markdown.append("## Root Directory\n")
        else:
            markdown.append(f"## {dir_name}/\n")
        
        markdown.append("| File | Dependencies |")
        markdown.append("|------|--------------|")
        
        for file in sorted(dirs[dir_name].keys()):
            deps = dirs[dir_name][file]
            if not deps:
                markdown.append(f"| `{file}` | - |")
            else:
                markdown.append(f"| `{file}` | `{'`, `'.join(sorted(deps))}` |")
        
        markdown.append("")
    
    return "\n".join(markdown)

if __name__ == "__main__":
    deps = analyze_dependencies()
    md = generate_markdown(deps)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(md)
    
    print(f"Dependencies analysis written to {OUTPUT_FILE}")
