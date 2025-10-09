# in infraware/utils/file_handler.py

import os
import yaml
import typer
from pathlib import Path

# File and directory patterns to ignore for better performance
IGNORED_DIRECTORIES = {
    # Version control and build artifacts
    '.git', '.svn', '.hg', '.bzr', 
    '__pycache__', '.pytest_cache', 'node_modules', 
    # Build and distribution
    'dist', 'build', '.tox', '.eggs', '*.egg-info',
    # IDE and editor files
    '.vscode', '.idea', '.vs', 
    # Operating system files
    '.DS_Store', 'Thumbs.db',
    # Temporary and cache
    'tmp', 'temp', '.cache', '.npm', '.yarn',
    # Documentation and assets (unless specifically needed)
    'docs', 'documentation', 'assets', 'images', 'media',
    # Test artifacts
    'coverage', '.coverage', '.nyc_output',
    # Package managers
    'vendor', 'packages'
}

IGNORED_FILE_EXTENSIONS = {
    # Binary and media files
    '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
    '.mp4', '.avi', '.mov', '.mp3', '.wav', '.pdf',
    # Archive files
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    # Database and logs
    '.db', '.sqlite', '.log', '.logs',
    # IDE and editor files
    '.swp', '.swo', '.tmp', '.temp', '.bak',
    # Package files
    '.jar', '.war', '.ear', '.deb', '.rpm'
}

def should_ignore_path(path: Path) -> bool:
    """Check if a path should be ignored for performance."""
    # Check if any part of the path matches ignored directories
    for part in path.parts:
        if part in IGNORED_DIRECTORIES or part.startswith('.'):
            return True
    
    # Check file extension
    if path.suffix.lower() in IGNORED_FILE_EXTENSIONS:
        return True
        
    return False

def load_rules_from_directory(rules_dir: str) -> list:
    """Loads all .yaml files from a directory into a single list of rules."""
    all_rules = []
    if not os.path.isdir(rules_dir):
        typer.secho(f"Warning: Rules directory '{rules_dir}' not found.", fg=typer.colors.YELLOW)
        return []
        
    for filename in os.listdir(rules_dir):
        if filename.endswith((".yaml", ".yml")):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, 'r') as f:
                try:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        all_rules.extend(rules)
                except yaml.YAMLError:
                    # Pass silently; validation command will catch this.
                    pass
    return all_rules

def load_ignores_from_directory(ignore_dir: str) -> list:
    """Loads all ignore files from a directory into a single list."""
    all_ignores = []
    if not os.path.isdir(ignore_dir):
        typer.secho(f"Warning: Ignore directory '{ignore_dir}' not found.", fg=typer.colors.YELLOW)
        return []

    for filename in os.listdir(ignore_dir):
        if filename.endswith((".yaml", ".yml")):
            filepath = os.path.join(ignore_dir, filename)
            with open(filepath, 'r') as f:
                try:
                    ignores = yaml.safe_load(f)
                    if ignores and 'ignore' in ignores and isinstance(ignores['ignore'], list):
                        all_ignores.extend(ignores['ignore'])
                except yaml.YAMLError as e:
                    typer.secho(f"Warning: Could not parse ignore file {filename}: {e}", fg=typer.colors.YELLOW)
    return all_ignores

def get_scannable_files(directory: str, max_files: int = 1000) -> list:
    """
    Get a list of scannable files from a directory, filtering out unnecessary files.
    
    Args:
        directory: Directory to scan
        max_files: Maximum number of files to return (performance limit)
        
    Returns:
        List of file paths that should be scanned
    """
    scannable_files = []
    target_extensions = {'.tf', '.json', '.yaml', '.yml', '.hcl'}
    
    directory_path = Path(directory)
    if not directory_path.exists():
        typer.secho(f"Warning: Directory '{directory}' not found.", fg=typer.colors.YELLOW)
        return []
    
    try:
        for file_path in directory_path.rglob('*'):
            # Skip if we've hit the limit
            if len(scannable_files) >= max_files:
                typer.secho(f"Warning: Limiting scan to {max_files} files for performance.", fg=typer.colors.YELLOW)
                break
                
            # Skip directories and ignored paths
            if file_path.is_dir() or should_ignore_path(file_path):
                continue
                
            # Only include relevant file types
            if file_path.suffix.lower() in target_extensions:
                scannable_files.append(str(file_path))
                
    except PermissionError as e:
        typer.secho(f"Warning: Permission denied accessing some files: {e}", fg=typer.colors.YELLOW)
    except Exception as e:
        typer.secho(f"Warning: Error scanning directory: {e}", fg=typer.colors.YELLOW)
    
    return scannable_files

def get_directory_summary(directory: str) -> dict:
    """
    Get a summary of files in a directory for quick overview.
    
    Returns:
        Dictionary with file counts and types
    """
    directory_path = Path(directory)
    if not directory_path.exists():
        return {"error": "Directory not found"}
    
    summary = {
        "total_files": 0,
        "scannable_files": 0,
        "ignored_files": 0,
        "file_types": {},
        "directories": 0
    }
    
    try:
        for item in directory_path.rglob('*'):
            if item.is_dir():
                summary["directories"] += 1
                continue
                
            summary["total_files"] += 1
            
            # Count by extension
            ext = item.suffix.lower()
            summary["file_types"][ext] = summary["file_types"].get(ext, 0) + 1
            
            # Check if scannable
            if should_ignore_path(item):
                summary["ignored_files"] += 1
            elif ext in {'.tf', '.json', '.yaml', '.yml', '.hcl'}:
                summary["scannable_files"] += 1
            else:
                summary["ignored_files"] += 1
                
    except Exception as e:
        summary["error"] = str(e)
    
    return summary