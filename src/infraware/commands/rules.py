# in src/infraware/commands/rules.py

import yaml
import typer
import os
import json # <-- New import for JSON output
from typing_extensions import Annotated
from rich.console import Console
from rich.table import Table

# Import our helper functions
from infraware.utils.file_handler import load_rules_from_directory

app = typer.Typer()
console = Console()

@app.command("list")
def list_rules(
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing rule files.")] = "rules",
    # --- New option for output format ---
    output: Annotated[str, typer.Option("--output", help="Output format ('console' or 'json').")] = "console"
):
    """Lists all available rules in the specified directory."""
    if output == "console":
        typer.echo(f"Listing rules from '{rules_dir}'...\n")
        
    rules = load_rules_from_directory(rules_dir)
    
    if not rules:
        if output == "console":
            typer.secho("No rules found.", fg=typer.colors.YELLOW)
        else:
            print("[]") # Print an empty JSON array if no rules are found
        raise typer.Exit()

    # --- New conditional output logic ---
    if output == "json":
        # Print the raw list of rules as a JSON object
        print(json.dumps(rules, indent=2))
    else:
        # The existing logic to print a beautiful table
        table = Table("Rule ID", "Severity", "Resource", "Description")
        for rule in rules:
            table.add_row(rule.get('id'), rule.get('severity'), rule.get('resource'), rule.get('description'))
        
        console.print(table)

# (The 'validate' and 'create' commands remain exactly the same as before)
@app.command("validate")
def validate_rules(
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing rule files.")] = "rules"
):
    """Validates the syntax and structure of all rule files in a directory."""
    typer.echo(f"Validating rules in '{rules_dir}'...")
    required_keys = {'id', 'severity', 'description', 'resource', 'attribute', 'value'}
    all_valid = True

    if not os.path.isdir(rules_dir):
        typer.secho(f"Error: Directory '{rules_dir}' not found.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    for filename in os.listdir(rules_dir):
        if filename.endswith((".yaml", ".yml")):
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    rules_in_file = yaml.safe_load(f)
                    if not isinstance(rules_in_file, list):
                        raise ValueError("File must contain a list of rules.")
                    for i, rule in enumerate(rules_in_file):
                        if not required_keys.issubset(rule.keys()):
                            raise ValueError(f"Rule #{i+1} is missing required keys.")
                typer.secho(f"  ✔ {filename} - OK", fg=typer.colors.GREEN)
            except Exception as e:
                typer.secho(f"  ✖ {filename} - FAILED: {e}", fg=typer.colors.RED)
                all_valid = False
    
    if all_valid:
        typer.secho("\nAll rule files are valid!", fg=typer.colors.GREEN)

@app.command("create")
def create_rule(
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory to save the new rule in.")] = "rules"
):
    """Interactively create a new rule file."""
    typer.echo("--- Creating a New Rule ---")
    
    if not os.path.isdir(rules_dir):
        os.makedirs(rules_dir)
        typer.echo(f"Created directory '{rules_dir}'.")

    rule = {}
    rule['id'] = typer.prompt("Rule ID (e.g., AWS-EC2-001)")
    rule['severity'] = typer.prompt("Severity (e.g., HIGH, MEDIUM, LOW)")
    rule['description'] = typer.prompt("Description")
    rule['resource'] = typer.prompt("Terraform Resource Type (e.g., aws_instance)")
    rule['attribute'] = typer.prompt("Attribute to check (e.g., instance_type)")
    rule['value'] = typer.prompt("Vulnerable value (e.g., t2.micro)")

    filename = typer.prompt("Enter a filename for the new rule (e.g., my_new_rule.yaml)")
    if not (filename.endswith(".yaml") or filename.endswith(".yml")):
        filename += ".yaml"
        
    filepath = os.path.join(rules_dir, filename)
    
    with open(filepath, 'w') as f:
        yaml.dump([rule], f, sort_keys=False)
        
    typer.secho(f"\nSuccess! Rule saved to {filepath}", fg=typer.colors.GREEN)