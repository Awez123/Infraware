# in infraware/commands/scan.py

import json
import typer
from typing_extensions import Annotated

# Import our helper functions from the utils module
from infraware.utils.file_handler import load_rules_from_directory, load_ignores_from_directory

app = typer.Typer()

@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to the terraform plan JSON file.")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing YAML rule files.")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Path to a directory containing ignore files.")] = None
):
    """
    Scans a Terraform plan file for vulnerabilities based on a set of rules.
    """
    typer.echo(f"Scanning plan: {plan_file}")
    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir:
        ignored_findings = load_ignores_from_directory(ignore_dir)

    try:
        with open(plan_file, 'r') as f: plan_data = json.load(f)
    except Exception as e:
        typer.secho(f"Error reading plan file: {e}", fg=typer.colors.RED, err=True); raise typer.Exit(code=1)

    vulnerabilities_found = 0
    ignored_count = 0
    resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
    
    for rule in rules:
        for resource in resources:
            if resource.get('type') == rule['resource']:
                attributes = resource.get('values', {})
                if rule['attribute'] in attributes and attributes[rule['attribute']] == rule['value']:
                    resource_full_name = f"{resource.get('type')}.{resource.get('name')}"
                    is_ignored = False
                    for ignored in ignored_findings:
                        if ignored['resource_name'] == resource.get('name'):
                            is_ignored = True
                            ignored_count += 1
                            break
                    
                    if not is_ignored:
                        vulnerabilities_found += 1
                        typer.secho("--- VULNERABILITY FOUND! ---", fg=typer.colors.RED, bold=True)
                        typer.echo(f"  Rule ID:      {rule['id']}")
                        typer.secho(f"  Severity:     {rule['severity']}", fg=typer.colors.YELLOW)
                        typer.echo(f"  Description:  {rule['description']}")
                        typer.echo(f"  Resource:     {resource_full_name}\n")

    typer.secho("--- Scan Summary ---", bold=True)
    if vulnerabilities_found > 0:
        typer.secho(f"Found {vulnerabilities_found} vulnerability(s).", fg=typer.colors.RED)
    else:
        typer.secho("No new vulnerabilities found. Good job!", fg=typer.colors.GREEN)
    
    if ignored_count > 0:
        typer.secho(f"Ignored {ignored_count} finding(s) based on ignore files.", fg=typer.colors.BLUE)