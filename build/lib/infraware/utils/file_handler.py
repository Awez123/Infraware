# in infraware/utils/file_handler.py

import os
import yaml
import typer

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